import os
import boto3
from botocore.vendored import requests
from requests.auth import HTTPBasicAuth

def handler(event, context):
    # set up environment variables
    endpoint = os.environ['ENDPOINT']
    roleARN = os.environ['ROLE_ARN']
    username = os.environ['MASTER_USERNAME']
    password = os.environ['MASTER_PASSWORD']
    apiurl = os.environ['APIURL']
    bucketName = os.environ['BUCKETNAME']

    s3 = boto3.client('s3')

    # create URL for security
    url = "https://" + endpoint + "/_plugins/_security/api/rolesmapping/all_access"

    # add in user and lambda role
    payload = {
        "users":[username],
        "backend_roles" : [roleARN]
    }

    # grant lambda IAM and user access to OpenSearch domain
    requests.put(url, auth = HTTPBasicAuth(username, password), json=payload)

    # create filename to be put in s3 for static website
    fileName = 'declare.js'

    # create body that should be in file
    stuff = "var jsonstr = '{}'".format(apiurl)
    uploadByteStream = bytes(stuff, 'utf-8')

    # put object into s3 bucket
    s3.put_object(Bucket=bucketName, Key=fileName, Body=uploadByteStream)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain'
        },
        'body': 'SUCCESS!!!'
    }