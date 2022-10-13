
# Valohai Self-Hosted CDK Tempalte

This template allows you provision AWS resources for a self-hosted Valohai installation.

* Security Groups
* EC2 instance (valohai-master)
* RDS PostgreSQL database 
* ElastiCache Redis
* LoadBalancer
* IAM Roles
    * ValohaiMaster (attached to `valohai-master`)
    * ValohaiWorker (attached to all workers by default)
* S3 Bucket
* AWS Secrets Manager Secret to store RDS password
* AWS Systems Manager Parameter Store to store the SSH Key of `valohai-master`

To deploy:
1. Follow the steps below to activate the virtual environment and install requirements.
2. Review the `cdk.json` file for configuration options (VPC, subnet, tags, etc.)

## Options

There are a few parameters in `cdk.json` that you can use:

* `vpc_id` - Which VPC should be used for all resources
* `roi_subnet` - Subnet for `valohai-master`
* `roi_assign_public_ip` - If `true` `valohai-master` will be placed on a public subnet inside the VPC and a Elastic IP will be attached to it
* `redis_subnets` - (private) subnets for Redis (a subnet group will be created with these subnets)
* `postgres_subnets` - (private) subnets for PostgreSQL (a subnet group will be created with these subnets)
* `default_s3_bucket_name` - S3 Bucket Name
* `tags` - Pass additional tags to all resources
* `allow_ssh_from` - List CIDR ranges that can SSH into `valohai-master`

## Run

Use the following step to activate your virtualenv.

```
$ source .venv/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
% .venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
$ pip install -r requirements.txt
```

At this point you can now synthesize the CloudFormation template for this code.

```
$ cdk synth
```

## Useful commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation
