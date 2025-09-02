package main

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/rds"
	"github.com/pulumi/pulumi-azure-native/sdk/go/azure/containerservice"
	"github.com/pulumi/pulumi-azure-native/sdk/go/azure/network"
	"github.com/pulumi/pulumi-azure-native/sdk/go/azure/resources"
	"github.com/pulumi/pulumi-gcp/sdk/v7/go/gcp/compute"
	"github.com/pulumi/pulumi-gcp/sdk/v7/go/gcp/container"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

// MultiCloudConfig represents the configuration for multi-cloud deployment
type MultiCloudConfig struct {
	ProjectName       string
	Environment       string
	EnableAWS         bool
	EnableGCP         bool
	EnableAzure       bool
	PrimaryCloud      string
	AWSRegion         string
	GCPRegion         string
	AzureLocation     string
	KubernetesVersion string
}

// AWSInfrastructure represents AWS infrastructure components
type AWSInfrastructure struct {
	VPC           *ec2.Vpc
	Subnets       []*ec2.Subnet
	EKSCluster    *eks.Cluster
	NodeGroup     *eks.NodeGroup
	RDSInstance   *rds.Instance
	SecurityGroup *ec2.SecurityGroup
}

// GCPInfrastructure represents GCP infrastructure components
type GCPInfrastructure struct {
	Network    *compute.Network
	Subnet     *compute.Subnetwork
	GKECluster *container.Cluster
	NodePool   *container.NodePool
}

// AzureInfrastructure represents Azure infrastructure components
type AzureInfrastructure struct {
	ResourceGroup *resources.ResourceGroup
	VNet          *network.VirtualNetwork
	Subnet        *network.Subnet
	AKSCluster    *containerservice.ManagedCluster
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Load configuration
		cfg := config.New(ctx, "")
		multiCloudConfig := &MultiCloudConfig{
			ProjectName:       cfg.Get("projectName"),
			Environment:       cfg.Get("environment"),
			EnableAWS:         cfg.GetBool("enableAWS"),
			EnableGCP:         cfg.GetBool("enableGCP"),
			EnableAzure:       cfg.GetBool("enableAzure"),
			PrimaryCloud:      cfg.Get("primaryCloud"),
			AWSRegion:         cfg.Get("awsRegion"),
			GCPRegion:         cfg.Get("gcpRegion"),
			AzureLocation:     cfg.Get("azureLocation"),
			KubernetesVersion: cfg.Get("kubernetesVersion"),
		}

		// Set default values
		if multiCloudConfig.ProjectName == "" {
			multiCloudConfig.ProjectName = "hackai"
		}
		if multiCloudConfig.Environment == "" {
			multiCloudConfig.Environment = "production"
		}
		if multiCloudConfig.AWSRegion == "" {
			multiCloudConfig.AWSRegion = "us-west-2"
		}
		if multiCloudConfig.GCPRegion == "" {
			multiCloudConfig.GCPRegion = "us-central1"
		}
		if multiCloudConfig.AzureLocation == "" {
			multiCloudConfig.AzureLocation = "East US"
		}
		if multiCloudConfig.KubernetesVersion == "" {
			multiCloudConfig.KubernetesVersion = "1.28"
		}

		// Deploy AWS infrastructure
		var awsInfra *AWSInfrastructure
		var err error
		if multiCloudConfig.EnableAWS {
			awsInfra, err = deployAWSInfrastructure(ctx, multiCloudConfig)
			if err != nil {
				return fmt.Errorf("failed to deploy AWS infrastructure: %w", err)
			}
		}

		// Deploy GCP infrastructure
		var gcpInfra *GCPInfrastructure
		if multiCloudConfig.EnableGCP {
			gcpInfra, err = deployGCPInfrastructure(ctx, multiCloudConfig)
			if err != nil {
				return fmt.Errorf("failed to deploy GCP infrastructure: %w", err)
			}
		}

		// Deploy Azure infrastructure
		var azureInfra *AzureInfrastructure
		if multiCloudConfig.EnableAzure {
			azureInfra, err = deployAzureInfrastructure(ctx, multiCloudConfig)
			if err != nil {
				return fmt.Errorf("failed to deploy Azure infrastructure: %w", err)
			}
		}

		// Export outputs
		return exportOutputs(ctx, multiCloudConfig, awsInfra, gcpInfra, azureInfra)
	})
}

func deployAWSInfrastructure(ctx *pulumi.Context, config *MultiCloudConfig) (*AWSInfrastructure, error) {
	// Create VPC
	vpc, err := ec2.NewVpc(ctx, fmt.Sprintf("%s-aws-vpc", config.ProjectName), &ec2.VpcArgs{
		CidrBlock:          pulumi.String("10.0.0.0/16"),
		EnableDnsHostnames: pulumi.Bool(true),
		EnableDnsSupport:   pulumi.Bool(true),
		Tags: pulumi.StringMap{
			"Name":        pulumi.String(fmt.Sprintf("%s-aws-vpc", config.ProjectName)),
			"Environment": pulumi.String(config.Environment),
			"ManagedBy":   pulumi.String("Pulumi"),
			"Cloud":       pulumi.String("AWS"),
		},
	})
	if err != nil {
		return nil, err
	}

	// Create Internet Gateway
	igw, err := ec2.NewInternetGateway(ctx, fmt.Sprintf("%s-aws-igw", config.ProjectName), &ec2.InternetGatewayArgs{
		VpcId: vpc.ID(),
		Tags: pulumi.StringMap{
			"Name":        pulumi.String(fmt.Sprintf("%s-aws-igw", config.ProjectName)),
			"Environment": pulumi.String(config.Environment),
		},
	})
	if err != nil {
		return nil, err
	}

	// Create subnets
	var subnets []*ec2.Subnet
	availabilityZones := []string{"a", "b", "c"}

	for i, az := range availabilityZones {
		// Public subnet
		publicSubnet, err := ec2.NewSubnet(ctx, fmt.Sprintf("%s-aws-public-subnet-%s", config.ProjectName, az), &ec2.SubnetArgs{
			VpcId:               vpc.ID(),
			CidrBlock:           pulumi.String(fmt.Sprintf("10.0.%d.0/24", i+1)),
			AvailabilityZone:    pulumi.String(fmt.Sprintf("%s%s", config.AWSRegion, az)),
			MapPublicIpOnLaunch: pulumi.Bool(true),
			Tags: pulumi.StringMap{
				"Name":                         pulumi.String(fmt.Sprintf("%s-aws-public-subnet-%s", config.ProjectName, az)),
				"Environment":                  pulumi.String(config.Environment),
				"kubernetes.io/role/elb":       pulumi.String("1"),
				"kubernetes.io/cluster/hackai": pulumi.String("shared"),
			},
		})
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, publicSubnet)

		// Private subnet
		privateSubnet, err := ec2.NewSubnet(ctx, fmt.Sprintf("%s-aws-private-subnet-%s", config.ProjectName, az), &ec2.SubnetArgs{
			VpcId:            vpc.ID(),
			CidrBlock:        pulumi.String(fmt.Sprintf("10.0.%d.0/24", i+10)),
			AvailabilityZone: pulumi.String(fmt.Sprintf("%s%s", config.AWSRegion, az)),
			Tags: pulumi.StringMap{
				"Name":                            pulumi.String(fmt.Sprintf("%s-aws-private-subnet-%s", config.ProjectName, az)),
				"Environment":                     pulumi.String(config.Environment),
				"kubernetes.io/role/internal-elb": pulumi.String("1"),
				"kubernetes.io/cluster/hackai":    pulumi.String("shared"),
			},
		})
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, privateSubnet)
	}

	// Create route table for public subnets
	publicRouteTable, err := ec2.NewRouteTable(ctx, fmt.Sprintf("%s-aws-public-rt", config.ProjectName), &ec2.RouteTableArgs{
		VpcId: vpc.ID(),
		Tags: pulumi.StringMap{
			"Name":        pulumi.String(fmt.Sprintf("%s-aws-public-rt", config.ProjectName)),
			"Environment": pulumi.String(config.Environment),
		},
	})
	if err != nil {
		return nil, err
	}

	// Create route to internet gateway
	_, err = ec2.NewRoute(ctx, fmt.Sprintf("%s-aws-public-route", config.ProjectName), &ec2.RouteArgs{
		RouteTableId:         publicRouteTable.ID(),
		DestinationCidrBlock: pulumi.String("0.0.0.0/0"),
		GatewayId:            igw.ID(),
	})
	if err != nil {
		return nil, err
	}

	// Create EKS cluster IAM role
	eksRole, err := iam.NewRole(ctx, fmt.Sprintf("%s-aws-eks-role", config.ProjectName), &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(`{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Action": "sts:AssumeRole",
					"Principal": {
						"Service": "eks.amazonaws.com"
					},
					"Effect": "Allow"
				}
			]
		}`),
		Tags: pulumi.StringMap{
			"Name":        pulumi.String(fmt.Sprintf("%s-aws-eks-role", config.ProjectName)),
			"Environment": pulumi.String(config.Environment),
		},
	})
	if err != nil {
		return nil, err
	}

	// Attach policies to EKS role
	_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-aws-eks-cluster-policy", config.ProjectName), &iam.RolePolicyAttachmentArgs{
		Role:      eksRole.Name,
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"),
	})
	if err != nil {
		return nil, err
	}

	// Create security group for EKS cluster
	eksSecurityGroup, err := ec2.NewSecurityGroup(ctx, fmt.Sprintf("%s-aws-eks-sg", config.ProjectName), &ec2.SecurityGroupArgs{
		VpcId:       vpc.ID(),
		Description: pulumi.String("Security group for EKS cluster"),
		Ingress: ec2.SecurityGroupIngressArray{
			&ec2.SecurityGroupIngressArgs{
				Protocol:   pulumi.String("tcp"),
				FromPort:   pulumi.Int(443),
				ToPort:     pulumi.Int(443),
				CidrBlocks: pulumi.StringArray{pulumi.String("0.0.0.0/0")},
			},
		},
		Egress: ec2.SecurityGroupEgressArray{
			&ec2.SecurityGroupEgressArgs{
				Protocol:   pulumi.String("-1"),
				FromPort:   pulumi.Int(0),
				ToPort:     pulumi.Int(0),
				CidrBlocks: pulumi.StringArray{pulumi.String("0.0.0.0/0")},
			},
		},
		Tags: pulumi.StringMap{
			"Name":        pulumi.String(fmt.Sprintf("%s-aws-eks-sg", config.ProjectName)),
			"Environment": pulumi.String(config.Environment),
		},
	})
	if err != nil {
		return nil, err
	}

	// Get subnet IDs for EKS cluster
	var subnetIds pulumi.StringArray
	for _, subnet := range subnets {
		subnetIds = append(subnetIds, subnet.ID())
	}

	// Create EKS cluster
	eksCluster, err := eks.NewCluster(ctx, fmt.Sprintf("%s-aws-eks", config.ProjectName), &eks.ClusterArgs{
		RoleArn: eksRole.Arn,
		Version: pulumi.String(config.KubernetesVersion),
		VpcConfig: &eks.ClusterVpcConfigArgs{
			SubnetIds:             subnetIds,
			SecurityGroupIds:      pulumi.StringArray{eksSecurityGroup.ID()},
			EndpointPrivateAccess: pulumi.Bool(true),
			EndpointPublicAccess:  pulumi.Bool(true),
		},
		EnabledClusterLogTypes: pulumi.StringArray{
			pulumi.String("api"),
			pulumi.String("audit"),
			pulumi.String("authenticator"),
			pulumi.String("controllerManager"),
			pulumi.String("scheduler"),
		},
		Tags: pulumi.StringMap{
			"Name":        pulumi.String(fmt.Sprintf("%s-aws-eks", config.ProjectName)),
			"Environment": pulumi.String(config.Environment),
			"ManagedBy":   pulumi.String("Pulumi"),
		},
	})
	if err != nil {
		return nil, err
	}

	// Create node group IAM role
	nodeGroupRole, err := iam.NewRole(ctx, fmt.Sprintf("%s-aws-nodegroup-role", config.ProjectName), &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(`{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Action": "sts:AssumeRole",
					"Principal": {
						"Service": "ec2.amazonaws.com"
					},
					"Effect": "Allow"
				}
			]
		}`),
	})
	if err != nil {
		return nil, err
	}

	// Attach policies to node group role
	policies := []string{
		"arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
		"arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
		"arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
	}

	for i, policy := range policies {
		_, err = iam.NewRolePolicyAttachment(ctx, fmt.Sprintf("%s-aws-nodegroup-policy-%d", config.ProjectName, i), &iam.RolePolicyAttachmentArgs{
			Role:      nodeGroupRole.Name,
			PolicyArn: pulumi.String(policy),
		})
		if err != nil {
			return nil, err
		}
	}

	// Create EKS node group
	nodeGroup, err := eks.NewNodeGroup(ctx, fmt.Sprintf("%s-aws-nodegroup", config.ProjectName), &eks.NodeGroupArgs{
		ClusterName:   eksCluster.Name,
		NodeRoleArn:   nodeGroupRole.Arn,
		SubnetIds:     subnetIds,
		InstanceTypes: pulumi.StringArray{pulumi.String("m5.large")},
		ScalingConfig: &eks.NodeGroupScalingConfigArgs{
			DesiredSize: pulumi.Int(3),
			MaxSize:     pulumi.Int(10),
			MinSize:     pulumi.Int(1),
		},
		UpdateConfig: &eks.NodeGroupUpdateConfigArgs{
			MaxUnavailablePercentage: pulumi.Int(25),
		},
		Tags: pulumi.StringMap{
			"Name":        pulumi.String(fmt.Sprintf("%s-aws-nodegroup", config.ProjectName)),
			"Environment": pulumi.String(config.Environment),
		},
	})
	if err != nil {
		return nil, err
	}

	return &AWSInfrastructure{
		VPC:           vpc,
		Subnets:       subnets,
		EKSCluster:    eksCluster,
		NodeGroup:     nodeGroup,
		SecurityGroup: eksSecurityGroup,
	}, nil
}

func deployGCPInfrastructure(ctx *pulumi.Context, config *MultiCloudConfig) (*GCPInfrastructure, error) {
	// Create VPC network
	network, err := compute.NewNetwork(ctx, fmt.Sprintf("%s-gcp-network", config.ProjectName), &compute.NetworkArgs{
		AutoCreateSubnetworks: pulumi.Bool(false),
		Description:           pulumi.String("VPC network for HackAI GCP infrastructure"),
	})
	if err != nil {
		return nil, err
	}

	// Create subnet
	subnet, err := compute.NewSubnetwork(ctx, fmt.Sprintf("%s-gcp-subnet", config.ProjectName), &compute.SubnetworkArgs{
		IpCidrRange: pulumi.String("10.1.0.0/16"),
		Network:     network.ID(),
		Region:      pulumi.String(config.GCPRegion),
		SecondaryIpRanges: compute.SubnetworkSecondaryIpRangeArray{
			&compute.SubnetworkSecondaryIpRangeArgs{
				RangeName:   pulumi.String("pods"),
				IpCidrRange: pulumi.String("10.2.0.0/16"),
			},
			&compute.SubnetworkSecondaryIpRangeArgs{
				RangeName:   pulumi.String("services"),
				IpCidrRange: pulumi.String("10.3.0.0/16"),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	// Create GKE cluster
	gkeCluster, err := container.NewCluster(ctx, fmt.Sprintf("%s-gcp-gke", config.ProjectName), &container.ClusterArgs{
		Location:         pulumi.String(config.GCPRegion),
		InitialNodeCount: pulumi.Int(1),
		Network:          network.Name,
		Subnetwork:       subnet.Name,
		IpAllocationPolicy: &container.ClusterIpAllocationPolicyArgs{
			ClusterSecondaryRangeName:  pulumi.String("pods"),
			ServicesSecondaryRangeName: pulumi.String("services"),
		},
		RemoveDefaultNodePool: pulumi.Bool(true),
		MinMasterVersion:      pulumi.String(config.KubernetesVersion),
		LoggingService:        pulumi.String("logging.googleapis.com/kubernetes"),
		MonitoringService:     pulumi.String("monitoring.googleapis.com/kubernetes"),
		AddonsConfig: &container.ClusterAddonsConfigArgs{
			HttpLoadBalancing: &container.ClusterAddonsConfigHttpLoadBalancingArgs{
				Disabled: pulumi.Bool(false),
			},
			HorizontalPodAutoscaling: &container.ClusterAddonsConfigHorizontalPodAutoscalingArgs{
				Disabled: pulumi.Bool(false),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	// Create node pool
	nodePool, err := container.NewNodePool(ctx, fmt.Sprintf("%s-gcp-nodepool", config.ProjectName), &container.NodePoolArgs{
		Location:  gkeCluster.Location,
		Cluster:   gkeCluster.Name,
		NodeCount: pulumi.Int(2),
		Version:   pulumi.String(config.KubernetesVersion),
		Management: &container.NodePoolManagementArgs{
			AutoRepair:  pulumi.Bool(true),
			AutoUpgrade: pulumi.Bool(true),
		},
		Autoscaling: &container.NodePoolAutoscalingArgs{
			MinNodeCount: pulumi.Int(1),
			MaxNodeCount: pulumi.Int(5),
		},
		NodeConfig: &container.NodePoolNodeConfigArgs{
			MachineType: pulumi.String("e2-standard-4"),
			DiskSizeGb:  pulumi.Int(50),
			DiskType:    pulumi.String("pd-ssd"),
			OauthScopes: pulumi.StringArray{
				pulumi.String("https://www.googleapis.com/auth/cloud-platform"),
			},
			Labels: pulumi.StringMap{
				"environment": pulumi.String(config.Environment),
				"managed-by":  pulumi.String("pulumi"),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return &GCPInfrastructure{
		Network:    network,
		Subnet:     subnet,
		GKECluster: gkeCluster,
		NodePool:   nodePool,
	}, nil
}

func deployAzureInfrastructure(ctx *pulumi.Context, config *MultiCloudConfig) (*AzureInfrastructure, error) {
	// Create resource group
	resourceGroup, err := resources.NewResourceGroup(ctx, fmt.Sprintf("%s-azure-rg", config.ProjectName), &resources.ResourceGroupArgs{
		Location: pulumi.String(config.AzureLocation),
		Tags: pulumi.StringMap{
			"Environment": pulumi.String(config.Environment),
			"ManagedBy":   pulumi.String("Pulumi"),
			"Cloud":       pulumi.String("Azure"),
		},
	})
	if err != nil {
		return nil, err
	}

	// Create AKS cluster
	aksCluster, err := containerservice.NewManagedCluster(ctx, fmt.Sprintf("%s-azure-aks", config.ProjectName), &containerservice.ManagedClusterArgs{
		ResourceGroupName: resourceGroup.Name,
		Location:          resourceGroup.Location,
		KubernetesVersion: pulumi.String(config.KubernetesVersion),
		DnsPrefix:         pulumi.String(fmt.Sprintf("%s-aks", config.ProjectName)),
		Identity: &containerservice.ManagedClusterIdentityArgs{
			Type: containerservice.ResourceIdentityTypeSystemAssigned,
		},
		AgentPoolProfiles: containerservice.ManagedClusterAgentPoolProfileArray{
			&containerservice.ManagedClusterAgentPoolProfileArgs{
				Name:              pulumi.String("default"),
				Count:             pulumi.Int(2),
				VmSize:            pulumi.String("Standard_D2s_v3"),
				Mode:              pulumi.String("System"),
				Type:              pulumi.String("VirtualMachineScaleSets"),
				EnableAutoScaling: pulumi.Bool(true),
				MinCount:          pulumi.Int(1),
				MaxCount:          pulumi.Int(5),
				OsDiskSizeGB:      pulumi.Int(50),
			},
		},
		NetworkProfile: &containerservice.ContainerServiceNetworkProfileArgs{
			NetworkPlugin: pulumi.String("azure"),
			ServiceCidr:   pulumi.String("10.2.0.0/16"),
			DnsServiceIP:  pulumi.String("10.2.0.10"),
		},
		Tags: pulumi.StringMap{
			"Environment": pulumi.String(config.Environment),
			"ManagedBy":   pulumi.String("Pulumi"),
		},
	})
	if err != nil {
		return nil, err
	}

	return &AzureInfrastructure{
		ResourceGroup: resourceGroup,
		AKSCluster:    aksCluster,
	}, nil
}

func exportOutputs(ctx *pulumi.Context, config *MultiCloudConfig, awsInfra *AWSInfrastructure, gcpInfra *GCPInfrastructure, azureInfra *AzureInfrastructure) error {
	// Export global configuration
	ctx.Export("projectName", pulumi.String(config.ProjectName))
	ctx.Export("environment", pulumi.String(config.Environment))
	ctx.Export("primaryCloud", pulumi.String(config.PrimaryCloud))

	// Export AWS outputs
	if awsInfra != nil {
		ctx.Export("aws:vpcId", awsInfra.VPC.ID())
		ctx.Export("aws:eksClusterName", awsInfra.EKSCluster.Name)
		ctx.Export("aws:eksClusterEndpoint", awsInfra.EKSCluster.Endpoint)
		ctx.Export("aws:eksClusterArn", awsInfra.EKSCluster.Arn)
	}

	// Export GCP outputs
	if gcpInfra != nil {
		ctx.Export("gcp:networkName", gcpInfra.Network.Name)
		ctx.Export("gcp:gkeClusterName", gcpInfra.GKECluster.Name)
		ctx.Export("gcp:gkeClusterEndpoint", gcpInfra.GKECluster.Endpoint)
	}

	// Export Azure outputs
	if azureInfra != nil {
		ctx.Export("azure:resourceGroupName", azureInfra.ResourceGroup.Name)
		ctx.Export("azure:aksClusterName", azureInfra.AKSCluster.Name)
		ctx.Export("azure:aksClusterFqdn", azureInfra.AKSCluster.Fqdn)
	}

	return nil
}
