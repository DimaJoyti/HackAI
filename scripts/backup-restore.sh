#!/bin/bash

# HackAI Backup and Disaster Recovery Script
# Provides comprehensive backup and restore capabilities for the HackAI platform

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="${NAMESPACE:-hackai-production}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/hackai}"
S3_BUCKET="${S3_BUCKET:-hackai-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    for tool in kubectl pg_dump redis-cli aws; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check Kubernetes connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    log_success "Prerequisites check completed"
}

# Backup PostgreSQL database
backup_postgres() {
    local timestamp="$1"
    local backup_file="$BACKUP_DIR/postgres-${timestamp}.sql.gz"
    
    log_info "Backing up PostgreSQL database..."
    
    # Get database credentials
    local db_secret=$(kubectl get secret postgresql -n "$NAMESPACE" -o jsonpath='{.data.postgres-password}' | base64 -d)
    local db_host=$(kubectl get service postgresql -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    
    # Create port-forward for database access
    kubectl port-forward service/postgresql 5432:5432 -n "$NAMESPACE" &
    local pf_pid=$!
    sleep 5
    
    # Perform backup
    PGPASSWORD="$db_secret" pg_dump -h localhost -p 5432 -U postgres -d hackai \
        --verbose --clean --if-exists --create | gzip > "$backup_file"
    
    # Kill port-forward
    kill $pf_pid 2>/dev/null || true
    
    if [ -f "$backup_file" ] && [ -s "$backup_file" ]; then
        log_success "PostgreSQL backup completed: $backup_file"
        echo "$backup_file"
    else
        log_error "PostgreSQL backup failed"
        return 1
    fi
}

# Backup Redis data
backup_redis() {
    local timestamp="$1"
    local backup_file="$BACKUP_DIR/redis-${timestamp}.rdb"
    
    log_info "Backing up Redis data..."
    
    # Get Redis password
    local redis_secret=$(kubectl get secret redis -n "$NAMESPACE" -o jsonpath='{.data.redis-password}' | base64 -d)
    
    # Create port-forward for Redis access
    kubectl port-forward service/redis-master 6379:6379 -n "$NAMESPACE" &
    local pf_pid=$!
    sleep 5
    
    # Trigger Redis save and copy RDB file
    redis-cli -h localhost -p 6379 -a "$redis_secret" BGSAVE
    
    # Wait for background save to complete
    while [ "$(redis-cli -h localhost -p 6379 -a "$redis_secret" LASTSAVE)" = "$(redis-cli -h localhost -p 6379 -a "$redis_secret" LASTSAVE)" ]; do
        sleep 1
    done
    
    # Copy RDB file from Redis pod
    local redis_pod=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=redis -o jsonpath='{.items[0].metadata.name}')
    kubectl cp "$NAMESPACE/$redis_pod:/data/dump.rdb" "$backup_file"
    
    # Kill port-forward
    kill $pf_pid 2>/dev/null || true
    
    if [ -f "$backup_file" ] && [ -s "$backup_file" ]; then
        log_success "Redis backup completed: $backup_file"
        echo "$backup_file"
    else
        log_error "Redis backup failed"
        return 1
    fi
}

# Backup Kubernetes resources
backup_k8s_resources() {
    local timestamp="$1"
    local backup_file="$BACKUP_DIR/k8s-resources-${timestamp}.yaml"
    
    log_info "Backing up Kubernetes resources..."
    
    # Backup all resources in the namespace
    kubectl get all,configmaps,secrets,pvc,ingress -n "$NAMESPACE" -o yaml > "$backup_file"
    
    # Backup custom resources
    kubectl get prometheusrules,servicemonitors -n "$NAMESPACE" -o yaml >> "$backup_file" 2>/dev/null || true
    
    if [ -f "$backup_file" ] && [ -s "$backup_file" ]; then
        log_success "Kubernetes resources backup completed: $backup_file"
        echo "$backup_file"
    else
        log_error "Kubernetes resources backup failed"
        return 1
    fi
}

# Backup application data
backup_app_data() {
    local timestamp="$1"
    local backup_file="$BACKUP_DIR/app-data-${timestamp}.tar.gz"
    
    log_info "Backing up application data..."
    
    # Create temporary directory for app data
    local temp_dir=$(mktemp -d)
    
    # Backup configuration files
    cp -r "$PROJECT_ROOT/configs" "$temp_dir/" 2>/dev/null || true
    
    # Backup certificates and keys (if any)
    kubectl get secrets -n "$NAMESPACE" -o yaml > "$temp_dir/secrets.yaml"
    
    # Backup persistent volume data
    local pvcs=$(kubectl get pvc -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
    for pvc in $pvcs; do
        log_info "Backing up PVC: $pvc"
        kubectl exec -n "$NAMESPACE" deployment/hackai-api-gateway -- tar czf - /data 2>/dev/null > "$temp_dir/${pvc}.tar.gz" || true
    done
    
    # Create final backup archive
    tar czf "$backup_file" -C "$temp_dir" .
    rm -rf "$temp_dir"
    
    if [ -f "$backup_file" ] && [ -s "$backup_file" ]; then
        log_success "Application data backup completed: $backup_file"
        echo "$backup_file"
    else
        log_error "Application data backup failed"
        return 1
    fi
}

# Upload backup to S3
upload_to_s3() {
    local backup_files=("$@")
    
    if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
        log_warning "AWS credentials not configured, skipping S3 upload"
        return 0
    fi
    
    log_info "Uploading backups to S3..."
    
    for file in "${backup_files[@]}"; do
        if [ -f "$file" ]; then
            local s3_key="$(basename "$file")"
            aws s3 cp "$file" "s3://$S3_BUCKET/$s3_key" --storage-class STANDARD_IA
            log_success "Uploaded $file to S3"
        fi
    done
}

# Create full backup
create_backup() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_files=()
    
    log_info "Starting full backup at $timestamp"
    
    check_prerequisites
    
    # Perform backups
    if postgres_backup=$(backup_postgres "$timestamp"); then
        backup_files+=("$postgres_backup")
    fi
    
    if redis_backup=$(backup_redis "$timestamp"); then
        backup_files+=("$redis_backup")
    fi
    
    if k8s_backup=$(backup_k8s_resources "$timestamp"); then
        backup_files+=("$k8s_backup")
    fi
    
    if app_backup=$(backup_app_data "$timestamp"); then
        backup_files+=("$app_backup")
    fi
    
    # Create backup manifest
    local manifest_file="$BACKUP_DIR/backup-manifest-${timestamp}.json"
    cat > "$manifest_file" <<EOF
{
  "timestamp": "$timestamp",
  "namespace": "$NAMESPACE",
  "files": [
$(printf '    "%s"' "${backup_files[@]}" | paste -sd, -)
  ],
  "size_bytes": $(du -cb "${backup_files[@]}" 2>/dev/null | tail -1 | cut -f1),
  "checksum": "$(sha256sum "${backup_files[@]}" | sha256sum | cut -d' ' -f1)"
}
EOF
    backup_files+=("$manifest_file")
    
    # Upload to S3 if configured
    upload_to_s3 "${backup_files[@]}"
    
    log_success "Full backup completed successfully"
    log_info "Backup files: ${backup_files[*]}"
}

# Restore PostgreSQL database
restore_postgres() {
    local backup_file="$1"
    
    log_info "Restoring PostgreSQL database from $backup_file"
    
    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    # Get database credentials
    local db_secret=$(kubectl get secret postgresql -n "$NAMESPACE" -o jsonpath='{.data.postgres-password}' | base64 -d)
    
    # Create port-forward for database access
    kubectl port-forward service/postgresql 5432:5432 -n "$NAMESPACE" &
    local pf_pid=$!
    sleep 5
    
    # Restore database
    gunzip -c "$backup_file" | PGPASSWORD="$db_secret" psql -h localhost -p 5432 -U postgres -d hackai
    
    # Kill port-forward
    kill $pf_pid 2>/dev/null || true
    
    log_success "PostgreSQL database restored successfully"
}

# Restore Redis data
restore_redis() {
    local backup_file="$1"
    
    log_info "Restoring Redis data from $backup_file"
    
    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    # Copy RDB file to Redis pod
    local redis_pod=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=redis -o jsonpath='{.items[0].metadata.name}')
    kubectl cp "$backup_file" "$NAMESPACE/$redis_pod:/data/dump.rdb"
    
    # Restart Redis to load the backup
    kubectl delete pod "$redis_pod" -n "$NAMESPACE"
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n "$NAMESPACE" --timeout=300s
    
    log_success "Redis data restored successfully"
}

# Restore from backup
restore_backup() {
    local timestamp="$1"
    
    if [ -z "$timestamp" ]; then
        log_error "Please specify backup timestamp"
        exit 1
    fi
    
    log_info "Starting restore from backup $timestamp"
    
    check_prerequisites
    
    # Find backup files
    local postgres_backup="$BACKUP_DIR/postgres-${timestamp}.sql.gz"
    local redis_backup="$BACKUP_DIR/redis-${timestamp}.rdb"
    local k8s_backup="$BACKUP_DIR/k8s-resources-${timestamp}.yaml"
    local app_backup="$BACKUP_DIR/app-data-${timestamp}.tar.gz"
    
    # Restore PostgreSQL
    if [ -f "$postgres_backup" ]; then
        restore_postgres "$postgres_backup"
    else
        log_warning "PostgreSQL backup not found: $postgres_backup"
    fi
    
    # Restore Redis
    if [ -f "$redis_backup" ]; then
        restore_redis "$redis_backup"
    else
        log_warning "Redis backup not found: $redis_backup"
    fi
    
    # Restore Kubernetes resources
    if [ -f "$k8s_backup" ]; then
        log_info "Restoring Kubernetes resources..."
        kubectl apply -f "$k8s_backup" -n "$NAMESPACE"
        log_success "Kubernetes resources restored"
    else
        log_warning "Kubernetes backup not found: $k8s_backup"
    fi
    
    # Restore application data
    if [ -f "$app_backup" ]; then
        log_info "Restoring application data..."
        local temp_dir=$(mktemp -d)
        tar xzf "$app_backup" -C "$temp_dir"
        
        # Restore secrets
        if [ -f "$temp_dir/secrets.yaml" ]; then
            kubectl apply -f "$temp_dir/secrets.yaml" -n "$NAMESPACE"
        fi
        
        rm -rf "$temp_dir"
        log_success "Application data restored"
    else
        log_warning "Application data backup not found: $app_backup"
    fi
    
    log_success "Restore completed successfully"
}

# List available backups
list_backups() {
    log_info "Available backups in $BACKUP_DIR:"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        log_warning "Backup directory does not exist: $BACKUP_DIR"
        return
    fi
    
    # List backup manifests
    for manifest in "$BACKUP_DIR"/backup-manifest-*.json; do
        if [ -f "$manifest" ]; then
            local timestamp=$(basename "$manifest" | sed 's/backup-manifest-\(.*\)\.json/\1/')
            local size=$(jq -r '.size_bytes' "$manifest" 2>/dev/null || echo "unknown")
            echo "  $timestamp ($(numfmt --to=iec "$size" 2>/dev/null || echo "$size bytes"))"
        fi
    done
}

# Cleanup old backups
cleanup_backups() {
    log_info "Cleaning up backups older than $RETENTION_DAYS days..."
    
    find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "*.rdb" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "*.yaml" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "*.json" -mtime +$RETENTION_DAYS -delete
    
    log_success "Cleanup completed"
}

# Main function
main() {
    case "${1:-}" in
        backup)
            create_backup
            ;;
        restore)
            restore_backup "${2:-}"
            ;;
        list)
            list_backups
            ;;
        cleanup)
            cleanup_backups
            ;;
        *)
            echo "Usage: $0 {backup|restore <timestamp>|list|cleanup}"
            echo ""
            echo "Commands:"
            echo "  backup              Create a full backup"
            echo "  restore <timestamp> Restore from backup"
            echo "  list                List available backups"
            echo "  cleanup             Remove old backups"
            echo ""
            echo "Environment variables:"
            echo "  NAMESPACE           Kubernetes namespace (default: hackai-production)"
            echo "  BACKUP_DIR          Backup directory (default: /var/backups/hackai)"
            echo "  S3_BUCKET           S3 bucket for remote backups"
            echo "  RETENTION_DAYS      Backup retention in days (default: 30)"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
