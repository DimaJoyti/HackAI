# HackAI Multi-Cloud Incident Response Runbook

## 🚨 **Emergency Contacts**

### **Escalation Matrix**
- **L1 Support**: platform-team@hackai.com
- **L2 Engineering**: engineering-team@hackai.com  
- **L3 Architecture**: architecture-team@hackai.com
- **Security Team**: security-team@hackai.com
- **On-Call Engineer**: +1-XXX-XXX-XXXX

### **External Contacts**
- **AWS Support**: Enterprise Support Case
- **GCP Support**: Premium Support Case
- **Azure Support**: Professional Direct Case

## 🔥 **Severity Levels**

### **P0 - Critical (Response: 15 minutes)**
- Complete service outage across all clouds
- Security breach or data compromise
- Financial impact > $10,000/hour

### **P1 - High (Response: 1 hour)**
- Single cloud provider outage
- Performance degradation > 50%
- Security vulnerability discovered

### **P2 - Medium (Response: 4 hours)**
- Non-critical service degradation
- Monitoring alerts firing
- Compliance issues

### **P3 - Low (Response: 24 hours)**
- Minor performance issues
- Documentation updates needed
- Enhancement requests

## 🚨 **Incident Response Process**

### **1. Detection & Alert**
```bash
# Check overall system health
kubectl get nodes --all-namespaces
kubectl get pods --all-namespaces | grep -v Running

# Check monitoring dashboards
# Grafana: http://grafana.hackai.com
# Prometheus: http://prometheus.hackai.com
# Jaeger: http://jaeger.hackai.com
```

### **2. Initial Assessment**
```bash
# Check cloud provider status
curl -s https://status.aws.amazon.com/
curl -s https://status.cloud.google.com/
curl -s https://status.azure.com/

# Check application health endpoints
curl -k https://api-aws.hackai.com/health
curl -k https://api-gcp.hackai.com/health
curl -k https://api-azure.hackai.com/health

# Check database connectivity
kubectl exec -it deployment/api-gateway -n hackai -- \
  psql -h postgres-service -U hackai -d hackai -c "SELECT 1;"
```

### **3. Communication**
```bash
# Create incident channel
# Slack: #incident-YYYY-MM-DD-HHMMSS

# Send initial notification
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"🚨 INCIDENT: [SEVERITY] [DESCRIPTION] - Investigation started"}' \
  $SLACK_WEBHOOK_URL

# Update status page
# https://status.hackai.com
```

### **4. Investigation & Diagnosis**

#### **Application Issues**
```bash
# Check application logs
kubectl logs -f deployment/api-gateway -n hackai --tail=100
kubectl logs -f deployment/user-service -n hackai --tail=100
kubectl logs -f deployment/scanner-service -n hackai --tail=100

# Check resource utilization
kubectl top nodes
kubectl top pods -n hackai --sort-by=cpu
kubectl top pods -n hackai --sort-by=memory

# Check events
kubectl get events --sort-by=.metadata.creationTimestamp -n hackai
```

#### **Database Issues**
```bash
# Check PostgreSQL status
kubectl exec -it deployment/postgres -n hackai -- \
  psql -U hackai -d hackai -c "SELECT * FROM pg_stat_activity;"

# Check Redis status
kubectl exec -it deployment/redis -n hackai -- redis-cli info

# Check database connections
kubectl exec -it deployment/postgres -n hackai -- \
  psql -U hackai -d hackai -c "SELECT count(*) FROM pg_stat_activity;"
```

#### **Network Issues**
```bash
# Check network policies
kubectl get networkpolicies -n hackai

# Check ingress status
kubectl get ingress -n hackai
kubectl describe ingress hackai-ingress -n hackai

# Test cross-cloud connectivity
kubectl exec -it deployment/api-gateway -n hackai -- \
  curl -k https://api-gcp.hackai.com/health
```

#### **Storage Issues**
```bash
# Check persistent volumes
kubectl get pv
kubectl get pvc -n hackai

# Check storage classes
kubectl get storageclass

# Check disk usage
kubectl exec -it deployment/postgres -n hackai -- df -h
```

### **5. Mitigation Strategies**

#### **Traffic Routing**
```bash
# Route traffic to healthy cloud
kubectl patch ingress hackai-ingress -n hackai -p \
  '{"spec":{"rules":[{"host":"api.hackai.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"api-gateway-gcp","port":{"number":80}}}}]}}]}}'

# Scale up healthy regions
kubectl scale deployment api-gateway --replicas=10 -n hackai
```

#### **Database Failover**
```bash
# Promote read replica to primary
kubectl exec -it deployment/postgres-replica -n hackai -- \
  psql -U hackai -d hackai -c "SELECT pg_promote();"

# Update application configuration
kubectl patch configmap app-config -n hackai -p \
  '{"data":{"DATABASE_HOST":"postgres-replica-service"}}'
```

#### **Emergency Scaling**
```bash
# Emergency horizontal scaling
kubectl scale deployment api-gateway --replicas=20 -n hackai
kubectl scale deployment user-service --replicas=10 -n hackai
kubectl scale deployment scanner-service --replicas=15 -n hackai

# Emergency vertical scaling
kubectl patch deployment api-gateway -n hackai -p \
  '{"spec":{"template":{"spec":{"containers":[{"name":"api-gateway","resources":{"requests":{"cpu":"2000m","memory":"4Gi"},"limits":{"cpu":"4000m","memory":"8Gi"}}}]}}}}'
```

### **6. Recovery Procedures**

#### **Application Recovery**
```bash
# Restart failed services
kubectl rollout restart deployment/api-gateway -n hackai
kubectl rollout restart deployment/user-service -n hackai

# Check rollout status
kubectl rollout status deployment/api-gateway -n hackai

# Verify health
kubectl get pods -n hackai | grep api-gateway
curl -k https://api.hackai.com/health
```

#### **Database Recovery**
```bash
# Restore from backup
kubectl exec -it deployment/postgres -n hackai -- \
  psql -U hackai -d hackai < /backups/latest-backup.sql

# Verify data integrity
kubectl exec -it deployment/postgres -n hackai -- \
  psql -U hackai -d hackai -c "SELECT count(*) FROM users;"
```

### **7. Post-Incident Activities**

#### **Verification**
```bash
# Run health checks
./scripts/health-check.sh

# Run smoke tests
./tests/smoke-tests.sh

# Verify monitoring
curl -s http://prometheus.hackai.com/api/v1/query?query=up | jq '.data.result'
```

#### **Communication**
```bash
# Send resolution notification
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"✅ RESOLVED: [INCIDENT] - All services restored"}' \
  $SLACK_WEBHOOK_URL

# Update status page
# Mark incident as resolved on https://status.hackai.com
```

## 📊 **Common Incident Scenarios**

### **Scenario 1: Single Cloud Provider Outage**
1. **Detection**: Monitoring alerts for specific cloud
2. **Assessment**: Verify cloud provider status
3. **Mitigation**: Route traffic to healthy clouds
4. **Recovery**: Monitor cloud provider restoration

### **Scenario 2: Database Connection Issues**
1. **Detection**: Database connection errors in logs
2. **Assessment**: Check database health and connections
3. **Mitigation**: Restart connection pools, scale replicas
4. **Recovery**: Verify application connectivity

### **Scenario 3: High Memory Usage**
1. **Detection**: Memory usage alerts
2. **Assessment**: Identify memory-consuming pods
3. **Mitigation**: Scale horizontally, restart pods
4. **Recovery**: Monitor memory usage trends

### **Scenario 4: SSL Certificate Expiration**
1. **Detection**: SSL certificate alerts
2. **Assessment**: Check certificate expiration dates
3. **Mitigation**: Renew certificates, update ingress
4. **Recovery**: Verify SSL connectivity

### **Scenario 5: Security Breach**
1. **Detection**: Security alerts or anomalous activity
2. **Assessment**: Isolate affected systems
3. **Mitigation**: Block malicious traffic, rotate secrets
4. **Recovery**: Forensic analysis, system hardening

## 🔧 **Tools & Commands**

### **Monitoring Commands**
```bash
# Check cluster health
kubectl cluster-info
kubectl get componentstatuses

# Check resource usage
kubectl top nodes
kubectl top pods --all-namespaces

# Check events
kubectl get events --sort-by=.metadata.creationTimestamp
```

### **Debugging Commands**
```bash
# Debug pod issues
kubectl describe pod POD_NAME -n NAMESPACE
kubectl logs POD_NAME -n NAMESPACE --previous

# Debug service issues
kubectl describe service SERVICE_NAME -n NAMESPACE
kubectl get endpoints SERVICE_NAME -n NAMESPACE

# Debug ingress issues
kubectl describe ingress INGRESS_NAME -n NAMESPACE
```

### **Recovery Commands**
```bash
# Rollback deployment
kubectl rollout undo deployment/DEPLOYMENT_NAME -n NAMESPACE

# Restart deployment
kubectl rollout restart deployment/DEPLOYMENT_NAME -n NAMESPACE

# Scale deployment
kubectl scale deployment DEPLOYMENT_NAME --replicas=N -n NAMESPACE
```

## 📋 **Incident Documentation Template**

### **Incident Report**
- **Incident ID**: INC-YYYY-MM-DD-HHMMSS
- **Severity**: P0/P1/P2/P3
- **Start Time**: YYYY-MM-DD HH:MM:SS UTC
- **End Time**: YYYY-MM-DD HH:MM:SS UTC
- **Duration**: X hours Y minutes
- **Affected Services**: List of affected services
- **Root Cause**: Detailed root cause analysis
- **Resolution**: Steps taken to resolve
- **Lessons Learned**: Improvements identified
- **Action Items**: Follow-up tasks with owners

### **Post-Mortem Process**
1. **Schedule post-mortem meeting** within 24 hours
2. **Gather timeline** of events and actions taken
3. **Identify root cause** and contributing factors
4. **Document lessons learned** and improvements
5. **Create action items** with owners and deadlines
6. **Share findings** with stakeholders
7. **Update runbooks** based on learnings

## 🚀 **Prevention & Improvement**

### **Proactive Measures**
- Regular disaster recovery testing
- Chaos engineering experiments
- Performance testing and capacity planning
- Security scanning and vulnerability assessments
- Infrastructure and application monitoring

### **Continuous Improvement**
- Regular runbook updates
- Team training and drills
- Tool and process improvements
- Automation of manual tasks
- Knowledge sharing and documentation
