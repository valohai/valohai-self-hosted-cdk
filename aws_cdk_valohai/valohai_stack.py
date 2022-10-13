from platform import platform
from constructs import Construct
from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_s3 as s3,
    aws_rds as rds,
    aws_elasticache as elasticache,
    aws_secretsmanager as secretsmanager,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as targets
)

class ValohaiSelfHostedStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        vpc_id = self.node.try_get_context("vpc_id")
        vpc = ec2.Vpc.from_lookup(self, "VPC", vpc_id=vpc_id)

        redis_subnets = self.node.try_get_context("redis_subnets")
        postgres_subnets = self.node.try_get_context("postgres_subnets")
        roi_subnet = self.node.try_get_context("roi_subnet")
        roi_assign_public_ip = self.node.try_get_context("roi_assign_public_ip")
        default_s3_bucket_name = self.node.try_get_context("default_s3_bucket_name")

        allow_ssh_from = self.node.try_get_context("allow_ssh_from")

        
        # LoadBalancer SG
        sg_loadbalancer = ec2.SecurityGroup(
            self,
            "valohai-sg-loadbalancer",
            security_group_name="valohai-sg-loadbalancer",
            vpc=vpc,
            allow_all_outbound=True
        )
        sg_loadbalancer.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80)
        )

        # Valohai SG Workers
        sg_workers = ec2.SecurityGroup(
            self,
            "valohai-sg-workers",
            security_group_name="valohai-sg-workers",
            vpc=vpc,
            allow_all_outbound=True
        )

        # Valohai SG Master
        sg_master = ec2.SecurityGroup(
            self,
            "valohai-sg-master",
            security_group_name="valohai-sg-master",
            vpc=vpc,
            allow_all_outbound=True
        )

        sg_master.add_ingress_rule(
            peer=ec2.Peer.security_group_id(sg_loadbalancer.security_group_id),
            connection=ec2.Port.tcp(8000),
            description="Allow access from LB"
        )

        for ip in allow_ssh_from :
            sg_master.add_ingress_rule(
                ec2.Peer.ipv4(ip),
                ec2.Port.tcp(22),
                "Allow SSH access from user"
            )

        # Valohai SG Database
        sg_database = ec2.SecurityGroup(
            self,
            "valohai-sg-database",
            security_group_name="valohai-sg-database",
            vpc=vpc,
            allow_all_outbound=True
        )
        sg_database.add_ingress_rule(
            ec2.Peer.security_group_id(sg_master.security_group_id),
            ec2.Port.tcp(5432),
            "Allow access from roi"
        )

        # Valohai SG Queue
        sg_redis_queue = ec2.SecurityGroup(
            self,
            "valohai-sg-queue",
            security_group_name="valohai-sg-queue",
            vpc=vpc,
            allow_all_outbound=True
        )

        # Allow connections from Roi
        sg_redis_queue.add_ingress_rule(
            ec2.Peer.security_group_id(sg_master.security_group_id),
            ec2.Port.tcp(6379),
            description = "Allow access from roi"
        )
        # Allow connections from workers
        sg_redis_queue.add_ingress_rule(
            ec2.Peer.security_group_id(sg_workers.security_group_id),
            ec2.Port.tcp(6379),
            description = "Allow access from workers"
        )
        
        # Default ValohaiWorkerPolicy
        # This is attached to all workers that are created by Valohai
        worker_policy_document_json = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "1",
                    "Effect": "Allow",
                    "Action": "autoscaling:SetInstanceProtection",
                    "Resource": "*"
                },
                {
                    "Sid": "2",
                    "Effect": "Allow",
                    "Action": "ec2:DescribeInstances",
                    "Resource": "*"
                }
            ]
        }

        worker_policy_document = iam.PolicyDocument.from_json(worker_policy_document_json)
        worker_policy = iam.ManagedPolicy(self, "ValohaiWorkerPolicy", managed_policy_name="ValohaiWorkerPolicy", document=worker_policy_document)

        # ValohaiWorkerRole
        role_worker = iam.Role(self, "ValohaiWorker", role_name="ValohaiWorker", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        role_worker.add_managed_policy(worker_policy)

        role_worker_instance_profile = iam.CfnInstanceProfile(
            self,
            "ValohaiWorkerInstanceProfile",
            roles=[role_worker.role_name],
            instance_profile_name="ValohaiWorkerInstanceProfile"
        )

        bucket = s3.Bucket(
            self,
            "valohai-data-test",
            bucket_name=default_s3_bucket_name,
            access_control=s3.BucketAccessControl.BUCKET_OWNER_FULL_CONTROL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL
        )

        master_policy_document_json = {
            "Version" : "2012-10-17",
            "Statement" : [
                {
                "Sid" : "2",
                "Effect" : "Allow",
                "Action" : [
                    "ec2:DescribeInstances",
                    "ec2:DescribeVpcs",
                    "ec2:DescribeKeyPairs",
                    "ec2:DescribeImages",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeInstanceTypes",
                    "ec2:DescribeLaunchTemplates",
                    "ec2:DescribeLaunchTemplateVersions",
                    "ec2:DescribeInstanceAttribute",
                    "ec2:CreateTags",
                    "ec2:DescribeInternetGateways",
                    "ec2:DescribeRouteTables",
                    "autoscaling:DescribeAutoScalingGroups",
                    "autoscaling:DescribeScalingActivities"
                ],
                "Resource" : "*"
                },
                {
                "Sid" : "AllowUpdatingSpotLaunchTemplates",
                "Effect" : "Allow",
                "Action" : [
                    "ec2:CreateLaunchTemplate",
                    "ec2:CreateLaunchTemplateVersion",
                    "ec2:ModifyLaunchTemplate",
                    "ec2:RunInstances",
                    "ec2:TerminateInstances",
                    "ec2:RebootInstances",
                    "autoscaling:UpdateAutoScalingGroup",
                    "autoscaling:CreateOrUpdateTags",
                    "autoscaling:SetDesiredCapacity",
                    "autoscaling:CreateAutoScalingGroup"
                ],
                "Resource" : "*",
                "Condition" : {
                    "ForAllValues:StringEquals" : {
                    "aws:ResourceTag/valohai" : "1"
                    }
                }
                },
                {
                "Sid" : "ServiceLinkedRole",
                "Effect" : "Allow",
                "Action" : "iam:CreateServiceLinkedRole",
                "Resource" : "arn:aws:iam::*:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
                },
                {
                "Sid" : "4",
                "Effect" : "Allow",
                "Action" : [
                    "iam:PassRole",
                    "iam:GetRole"
                ],
                "Resource" : role_worker.role_arn
                },
                {
                "Sid" : "0",
                "Effect" : "Allow",
                
                "Action" : [
                    "secretsmanager:GetResourcePolicy",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecretVersionIds"
                ],
                "Resource" : "*",
                "Condition" : {
                    "StringEquals" : {
                    "secretsmanager:ResourceTag/valohai" : "1"
                    }
                }
                },
                {
                "Action" : "secretsmanager:GetRandomPassword",
                "Resource" : "*",
                "Effect" : "Allow",
                "Sid" : "1"
                },
                {
                "Effect" : "Allow",
                "Action" : "s3:*",
                "Resource" : [
                    bucket.bucket_arn,
                    f'{bucket.bucket_arn}/*'
                ]
                },
                {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                    "logs:DescribeLogGroups"
                ],
                "Resource": [
                    "arn:aws:logs:*:*:log-group:*",
                    "arn:aws:logs:*:*:log-group:*:log-stream:",
                    "arn:aws:logs:*:*:log-group:*:log-stream:*"
                ]
                }
            ]
            }

        master_policy_document = iam.PolicyDocument.from_json(master_policy_document_json)
        master_policy = iam.ManagedPolicy(self, "ValohaiMasterPolicy",  managed_policy_name="ValohaiMasterPolicy", document=master_policy_document)
        
        # ValohaiWorkerRole
        role_master = iam.Role(self, "ValohaiMaster", role_name="ValohaiMaster", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        role_master.add_managed_policy(master_policy)

        ubuntu = ec2.MachineImage.from_ssm_parameter('/aws/service/canonical/ubuntu/server/focal/stable/current/amd64/hvm/ebs-gp2/ami-id')

        # Generate a Key Pair and save the Private Key to AWS Systems Manager Parameter Store
        master_key_pair = ec2.CfnKeyPair(self, "valohai-master-key-pair", key_name="valohai-master-key-pair")

        if roi_assign_public_ip :
            roi_subnet = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC)
        else :
            roi_subnet = ec2.SubnetSelection(subnet_filters=[ec2.SubnetFilter.by_ids([roi_subnet])])


        roi_instance_disk = ec2.BlockDevice(device_name="/dev/sda1", volume=ec2.BlockDeviceVolume.ebs(64))

        roi_instance = ec2.Instance(self, "ValohaiRoiEC2",
            instance_name="valohai-master",
            instance_type=ec2.InstanceType("m5a.xlarge"),
            machine_image=ubuntu,
            key_name=master_key_pair.key_name,
            vpc = vpc,
            role = role_master,
            vpc_subnets=roi_subnet,
            security_group=sg_master,
            block_devices=[roi_instance_disk]
        )

        if roi_assign_public_ip :
            roi_instance_eip = ec2.CfnEIP(self, "ValohaiRoiElasticIp", instance_id=roi_instance.instance_id)

        lb = elbv2.ApplicationLoadBalancer(
            self, "valohai-roi-lb",
            load_balancer_name="valohai-roi-lb",
            vpc=vpc,
            internet_facing=True,
            security_group=sg_loadbalancer
        )

        listener = lb.add_listener("Listener", port=80)
        listener.add_targets("Target", port=8000, targets=[targets.InstanceTarget(roi_instance)])
        listener.connections.allow_default_port_from_any_ipv4("Open to the world")

        engine = rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_2)

        db_subnet_group = rds.SubnetGroup(self,
            id = "valohai_postgres_subnet_group",
            subnet_group_name="valohai_postgres_subnet_group",
            vpc = vpc,
            description = "Subnet group for Valohai Roi Database (PostgreSQL)",
            vpc_subnets = ec2.SubnetSelection(subnet_filters=[ec2.SubnetFilter.by_ids(postgres_subnets)])
        )

        valohai_roicluster_secret = secretsmanager.Secret(self, "ValohaiRoiDBCredentials",
            secret_name ="valohai-roidb-credentials",
            description ="Valohai Roi PostgresSQL Credentials",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_characters ="\"@/\\ '",
                exclude_punctuation=True,
                generate_string_key ="password",
                password_length =30,
                secret_string_template='{"username":"valohai"}'
            )
        )

        cluster_credentials = rds.Credentials.from_secret(valohai_roicluster_secret, "valohai")

        rds_instance = rds.DatabaseInstance(self, "ValohaiRoiDB",
            engine=engine,
            instance_type=ec2.InstanceType("m5.xlarge"),
            vpc=vpc,
            credentials=cluster_credentials,
            security_groups=[sg_database],
            port=5432,
            multi_az=True,
            publicly_accessible=False,
            subnet_group=db_subnet_group,
            database_name="roi"
        )

        cache_subnet_group = elasticache.CfnSubnetGroup(
            scope=self,
            cache_subnet_group_name="valohai-redis-cache-subnet-group",
            id="valohai_redis_cache_subnet_group",
            subnet_ids=redis_subnets,
            description="subnet group for redis job queue in valohai",
        )

        redis_cluster = elasticache.CfnCacheCluster(
            scope=self,
            id="valohai-queue-redis",
            cluster_name="valohai-queue-redis",
            engine="redis",
            cache_node_type="cache.m5.xlarge",
            num_cache_nodes=1,
            cache_subnet_group_name=cache_subnet_group.cache_subnet_group_name,
            vpc_security_group_ids=[sg_redis_queue.security_group_id]
        )

        # Need to explicitly add the dependency
        # https://github.com/aws/aws-cdk/issues/6935#issuecomment-612637197
        redis_cluster.add_depends_on(cache_subnet_group); 
