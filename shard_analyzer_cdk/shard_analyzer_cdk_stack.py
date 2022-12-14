from aws_cdk import (
    CfnOutput,
    Stack,
    aws_lambda as _lambda,
    aws_apigateway as apigw,
    aws_opensearchservice as opensearch,
    aws_logs as logs,
    aws_iam as iam,
    aws_logs_destinations as destinations,
    SecretValue,
    triggers,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    Duration,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
)
from constructs import Construct
import random

# DOMAIN_NAME = 'ShardAnalyzer-OpenSearch-Logs'
REGIONS_TO_MONITOR='["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "sa-east-1"]'
MASTER_USERNAME = 'admin'
MASTER_PASSWORD = 'HappyClip#1!'

class ShardAnalyzerCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create Lambda Function
        my_lambda = _lambda.Function(
            self, 'ShardAnalyzerLambda',
            runtime=_lambda.Runtime.GO_1_X,
            code=_lambda.Code.from_asset('lambda'),
            handler='main',
        )

        # Create API gateway for lambda function
        api = apigw.LambdaRestApi(
            self, 'ShardAnalyzerEndpoint', handler=my_lambda, proxy=False
        )

        # create POST method and enable CORS
        items = api.root.add_resource("items")
        items.add_method("POST")
        items.add_cors_preflight(
            allow_origins=["*"], 
            allow_methods=["POST"],
        )

        # create OpenSearch Domain
        domain = opensearch.Domain(self, "ShardAnalyzerOpenSearchDomain",
            version=opensearch.EngineVersion.OPENSEARCH_1_2,
            enforce_https=True,
            node_to_node_encryption=True,
            encryption_at_rest={
                "enabled": True
            },
            use_unsigned_basic_auth=True,
            fine_grained_access_control={
                "master_user_name": MASTER_USERNAME,
                "master_user_password": SecretValue.unsafe_plain_text(MASTER_PASSWORD)
            },
        )

        # Lambda for CW logs
        lambda_func_cw_logs = _lambda.Function(
            self, 'CWLogsToOpenSearch',
            runtime = _lambda.Runtime.NODEJS_12_X,
            code=_lambda.Code.from_asset('lambdaCloudWatch'),
            handler='index.handler',
        )

        # Load Amazon OpenSearch Service Domain to env variable
        lambda_func_cw_logs.add_environment('DOMAIN_ENDPOINT', domain.domain_endpoint)

        # When the domain is created here, restrict access
        lambda_func_cw_logs.add_to_role_policy(iam.PolicyStatement(actions=['es:*'],
            resources=['*']))

        # The function needs to read CW Logs. Restrict
        lambda_func_cw_logs.add_to_role_policy(iam.PolicyStatement(actions=['logs:*'],
            resources=['*']))

        # create subscription filter
        logs.SubscriptionFilter(self, "lambdaSubscription",
            log_group=my_lambda.log_group,
            destination=destinations.LambdaDestination(lambda_func_cw_logs),
            filter_pattern=logs.FilterPattern.any_term("Details", "runtime error", "reflect")
        )

        # Grant lambda ability to write to domain
        domain.grant_read_write(lambda_func_cw_logs.role)

        # create random int to append to bucket name
        randomInt = random.randint(0, 10000)
        # create S3 bucket
        website_bucket = s3.Bucket(self, "ShardAnalyzerWebsiteBucket" + str(randomInt), 
        )
        
        # add files to s3 bucket
        s3deploy.BucketDeployment(self, "ShardAnalyzerDeployWebsite",
            sources=[s3deploy.Source.asset("HTML")],
            destination_bucket=website_bucket,
        )

        # Create cloudfront for public entry point
        originAccessIdentity = cloudfront.OriginAccessIdentity(self, 'OriginAccessIdentity')
        website_bucket.grant_read(originAccessIdentity)
        distribution = cloudfront.Distribution(self, "Distribution",
            default_root_object='index.html',
            default_behavior=cloudfront.BehaviorOptions(origin=origins.S3Origin(website_bucket, origin_access_identity=originAccessIdentity))
        )

        # Create trigger function that will add lambda_func_cw_logs IAM role to all_access backend role and will add APIGW endpoint to website
        trigger_function = triggers.TriggerFunction(
            self, "MyTrigger", 
            runtime=_lambda.Runtime.PYTHON_3_7,
            code = _lambda.Code.from_asset('triggerfunction'),
            handler='hello.handler',
            timeout=Duration.minutes(5)
        )

        # grant lambda function write to s3 bucket
        website_bucket.grant_write(trigger_function)

        # provide domain endpoint, role arn, username and password to lambda function
        trigger_function.add_environment('ENDPOINT', domain.domain_endpoint)
        trigger_function.add_environment('ROLE_ARN', lambda_func_cw_logs.role.role_arn)
        trigger_function.add_environment('MASTER_USERNAME', MASTER_USERNAME)
        trigger_function.add_environment('MASTER_PASSWORD', MASTER_PASSWORD)
        trigger_function.add_environment('APIURL', api.url+"items")
        trigger_function.add_environment('BUCKETNAME', website_bucket.bucket_name)

        # make sure trigger function executes after deployment
        trigger_function.execute_after(self)

        # CFN Outputs
        CfnOutput(self, "Cloudfront Distribution Domain name (URL to access website): ", value=distribution.distribution_domain_name)
        CfnOutput(self, "OpenSearch Dashboard URL", value="https://" + domain.domain_endpoint + "/_dashboards")
        CfnOutput(self, "OpenSearch Credentials", value="Username: " + MASTER_USERNAME + "\nPassword: " + MASTER_PASSWORD)