# HackAI Multi-Cloud Disaster Recovery Runbook

## 🎯 **Recovery Objectives**

### **Recovery Time Objective (RTO): 60 minutes**
- Maximum acceptable downtime for critical services
- Target: Full service restoration within 1 hour

### **Recovery Point Objective (RPO): 15 minutes**
- Maximum acceptable data loss
- Target: Data loss limited to last 15 minutes

### **Availability Target: 99.99%**
- Annual downtime budget: 52.56 minutes
- Monthly downtime budget: 4.38 minutes

## 🌍 **Multi-Cloud DR Strategy**

### **Primary-Secondary-Tertiary Model**
```
Primary (AWS - 60%)     Secondary (GCP - 25%)    Tertiary (Azure - 15%)
├── Active workloads    ├── Warm standby         ├── Cold standby
├── Live databases      ├── Read replicas        ├── Backup storage
├── Real-time traffic   ├── Batch processing     ├── DR testing
└── Full capacity       └── 50% capacity         └── 25% capacity
```

### **Data Replication Strategy**
- **Synchronous replication**: Critical data (user accounts, security configs)
- **Asynchronous replication**: Application data (scan results, logs)
- **Cross-cloud backups**: Daily encrypted backups to all clouds
- **Point-in-time recovery**: 30-day retention with hourly snapshots

## 🚨 **Disaster Scenarios**

### **Scenario 1: Single Cloud Provider Outage**
**Impact**: 60% capacity loss (AWS), 25% capacity loss (GCP), 15% capacity loss (Azure)
**RTO**: 15 minutes | **RPO**: 5 minutes

#### **Detection**
```bash
# Monitor cloud provider status
curl -s https://status.aws.amazon.com/ | grep -i "Service is operating normally"
curl -s https://status.cloud.google.com/ | grep -i "All services are operational"
curl -s https://status.azure.com/ | grep -i "All services are running normally"

# Check cluster connectivity
kubectl cluster-info --context aws-production
kubectl cluster-info --context gcp-production
kubectl cluster-info --context azure-production
```

#### **Response Actions**
```bash
# 1. Activate traffic routing to healthy clouds
kubectl patch ingress global-ingress -n hackai -p \
  '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/upstream-hash-by":"$request_uri"}}}'

# 2. Scale up secondary cloud capacity
kubectl scale deployment api-gateway --replicas=20 --context gcp-production -n hackai
kubectl scale deployment user-service --replicas=10 --context gcp-production -n hackai

# 3. Promote read replicas if database affected
kubectl exec -it postgres-replica --context gcp-production -n hackai -- \
  psql -U hackai -d hackai -c "SELECT pg_promote();"

# 4. Update DNS to route traffic
# Update Route53/Cloud DNS records to point to healthy endpoints
```

### **Scenario 2: Regional Disaster**
**Impact**: Complete regional failure
**RTO**: 45 minutes | **RPO**: 15 minutes

#### **Response Actions**
```bash
# 1. Activate DR region
terraform apply -var="dr_activation=true" -target="module.dr_region"

# 2. Restore databases from backup
kubectl apply -f deployments/dr/database-restore.yaml

# 3. Deploy applications to DR region
kubectl apply -f deployments/dr/ --context dr-region

# 4. Update global load balancer
# Route all traffic to DR region
```

### **Scenario 3: Complete Infrastructure Failure**
**Impact**: All cloud providers affected
**RTO**: 60 minutes | **RPO**: 15 minutes

#### **Response Actions**
```bash
# 1. Activate emergency infrastructure
terraform apply -var-file="emergency.tfvars" -target="module.emergency_infra"

# 2. Restore from cross-cloud backups
./scripts/emergency-restore.sh

# 3. Communicate with stakeholders
# Send emergency notifications to all users
```

## 🔄 **Recovery Procedures**

### **Database Recovery**

#### **PostgreSQL Recovery**
```bash
# 1. Stop application traffic to database
kubectl scale deployment api-gateway --replicas=0 -n hackai

# 2. Restore from latest backup
kubectl exec -it postgres-primary -n hackai -- \
  pg_restore -U hackai -d hackai /backups/latest-backup.dump

# 3. Verify data integrity
kubectl exec -it postgres-primary -n hackai -- \
  psql -U hackai -d hackai -c "SELECT count(*) FROM users; SELECT count(*) FROM scans;"

# 4. Start replication to other clouds
kubectl exec -it postgres-primary -n hackai -- \
  psql -U hackai -d hackai -c "SELECT pg_start_backup('dr_restore');"

# 5. Resume application traffic
kubectl scale deployment api-gateway --replicas=5 -n hackai
```

#### **Redis Recovery**
```bash
# 1. Restore Redis from backup
kubectl exec -it redis-primary -n hackai -- \
  redis-cli --rdb /backups/latest-redis.rdb

# 2. Verify cache functionality
kubectl exec -it redis-primary -n hackai -- redis-cli ping

# 3. Warm up cache
./scripts/cache-warmup.sh
```

### **Application Recovery**

#### **Kubernetes Cluster Recovery**
```bash
# 1. Verify cluster health
kubectl get nodes
kubectl get pods --all-namespaces

# 2. Deploy core services first
kubectl apply -f deployments/core/ -n hackai

# 3. Deploy application services
kubectl apply -f deployments/apps/ -n hackai

# 4. Verify service health
kubectl get pods -n hackai
./scripts/health-check.sh
```

#### **Serverless Functions Recovery**
```bash
# 1. Redeploy Lambda functions
cd serverless/aws-lambda
for func in */; do
  aws lambda update-function-code \
    --function-name "hackai-production-${func%/}" \
    --zip-file "fileb://${func%/}.zip"
done

# 2. Verify function execution
aws lambda invoke --function-name hackai-production-auto-scaler response.json
cat response.json
```

### **Network Recovery**

#### **DNS and Load Balancer Recovery**
```bash
# 1. Update DNS records
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456789 \
  --change-batch file://dns-failover.json

# 2. Verify DNS propagation
dig api.hackai.com
nslookup api.hackai.com

# 3. Test load balancer health
curl -k https://api.hackai.com/health
```

## 📊 **Recovery Validation**

### **Health Check Procedures**
```bash
# 1. Infrastructure health
kubectl get nodes --all-namespaces
kubectl get pods --all-namespaces | grep -v Running

# 2. Application health
curl -k https://api.hackai.com/health
curl -k https://api.hackai.com/api/v1/status

# 3. Database connectivity
kubectl exec -it deployment/api-gateway -n hackai -- \
  psql -h postgres-service -U hackai -d hackai -c "SELECT 1;"

# 4. Cache connectivity
kubectl exec -it deployment/api-gateway -n hackai -- \
  redis-cli -h redis-service ping

# 5. Cross-cloud connectivity
./tests/cross-cloud-connectivity.sh

# 6. Performance validation
./tests/performance/smoke-test.sh
```

### **Data Integrity Verification**
```bash
# 1. Database consistency checks
kubectl exec -it postgres-primary -n hackai -- \
  psql -U hackai -d hackai -c "SELECT pg_database_size('hackai');"

# 2. User data verification
kubectl exec -it postgres-primary -n hackai -- \
  psql -U hackai -d hackai -c "SELECT count(*) FROM users WHERE created_at > NOW() - INTERVAL '1 day';"

# 3. Scan data verification
kubectl exec -it postgres-primary -n hackai -- \
  psql -U hackai -d hackai -c "SELECT count(*) FROM scans WHERE status = 'completed';"

# 4. Cross-cloud data sync verification
./scripts/verify-data-sync.sh
```

## 🔧 **DR Testing Procedures**

### **Monthly DR Tests**
```bash
# 1. Planned failover test (first Saturday of each month)
./scripts/dr-test-failover.sh --type=planned --duration=30m

# 2. Database recovery test
./scripts/dr-test-database.sh --backup-age=24h

# 3. Cross-cloud connectivity test
./scripts/dr-test-connectivity.sh --all-clouds

# 4. Performance validation
./tests/performance/dr-performance-test.sh
```

### **Quarterly DR Drills**
```bash
# 1. Full disaster simulation
./scripts/dr-drill-full.sh --scenario=regional-outage

# 2. Communication test
./scripts/dr-drill-communication.sh

# 3. Team response validation
./scripts/dr-drill-team-response.sh

# 4. Recovery time measurement
./scripts/dr-drill-rto-measurement.sh
```

## 📋 **DR Checklist**

### **Pre-Disaster Preparation**
- [ ] Backup verification completed
- [ ] DR infrastructure tested
- [ ] Team contact information updated
- [ ] Runbooks reviewed and updated
- [ ] Recovery procedures tested
- [ ] Monitoring and alerting verified

### **During Disaster Response**
- [ ] Incident declared and team notified
- [ ] Impact assessment completed
- [ ] Recovery procedures initiated
- [ ] Stakeholder communication sent
- [ ] Progress updates provided
- [ ] Recovery validation performed

### **Post-Disaster Activities**
- [ ] Service restoration verified
- [ ] Data integrity confirmed
- [ ] Performance validated
- [ ] Stakeholder notification sent
- [ ] Post-mortem scheduled
- [ ] Lessons learned documented

## 📞 **Communication Plan**

### **Internal Communication**
1. **Immediate**: Slack #incident-response channel
2. **15 minutes**: Email to engineering team
3. **30 minutes**: Executive briefing
4. **Hourly**: Progress updates to stakeholders

### **External Communication**
1. **Status page**: https://status.hackai.com
2. **Customer email**: Major incidents affecting service
3. **Social media**: Significant outages only
4. **Press release**: If required for major incidents

### **Communication Templates**

#### **Initial Notification**
```
Subject: [URGENT] HackAI Service Disruption - Investigation Underway

We are currently investigating reports of service disruption affecting our platform. 
Our engineering team has been notified and is working to resolve the issue.

Estimated Resolution: [TIME]
Next Update: [TIME]

Status Page: https://status.hackai.com
```

#### **Resolution Notification**
```
Subject: [RESOLVED] HackAI Service Restored

The service disruption affecting our platform has been resolved. All services are 
now operating normally.

Incident Duration: [DURATION]
Root Cause: [BRIEF DESCRIPTION]

We apologize for any inconvenience caused. A detailed post-mortem will be published 
within 48 hours.
```

## 🔄 **Continuous Improvement**

### **DR Metrics**
- **RTO Achievement**: Measure actual vs. target recovery time
- **RPO Achievement**: Measure actual vs. target data loss
- **Test Success Rate**: Percentage of successful DR tests
- **Mean Time to Recovery**: Average time for full service restoration

### **Regular Reviews**
- **Monthly**: DR test results and metrics review
- **Quarterly**: DR strategy and procedures review
- **Annually**: Complete DR plan review and update

### **Training and Awareness**
- **New hire training**: DR procedures and responsibilities
- **Quarterly drills**: Team response and coordination
- **Annual training**: Updated procedures and lessons learned
- **Cross-training**: Ensure multiple team members can execute procedures
