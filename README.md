
# ShardAnalyzer CDK

This CDK starts up all the tools necessary to use the ShardAnalyzer program. The front-end is hosted on an S3 bucket using cloudfront as a public entry point. This webpage will make calls to a lambda function to process user inputs. The lambda's cloudwatch logs will then be streamed to an OpenSearch domain. The username and password for the OpenSearch domain are hard-coded within shard_analyzer_cdk/shard_analyzer_cdk_stack.py. 

To get started deploying the ShardAnalyzer web application, please refer to AWS's CDK documentation: 

https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html

https://aws.amazon.com/getting-started/guides/setup-cdk/
