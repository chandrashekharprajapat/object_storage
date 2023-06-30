import datetime
import hashlib
import hmac
import xmltodict
import base64
import json
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import requests
from creds import endpoint,access_key,secret_key

app = Flask(__name__)
api = Api(app)

# Ceph S3 endpoint and access credentials



class Bucket(Resource):
    def put(self):
        request_data = request.get_json()
        if 'bucket_name' not in request_data:
            return ({'error': 'Bucket name is required'}), 400

        bucket_name = request_data['bucket_name']
        url = f'{endpoint}/{bucket_name}'

        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

        # Generate the string to sign
        string_to_sign = f'PUT\n\n\n{timestamp}\n/{bucket_name}'

        # Generate the signature
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')

        # Create the Authorization header value
        authorization_header = f'AWS {access_key}:{signature}'

        # Construct the headers for the request
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header,
        }

        # Send the PUT request to create the bucket
        response = requests.put(url, headers=headers)

        # Check the response status code
        if response.status_code == 200:
            return ({'message': f'Bucket {bucket_name} created successfully'}), 200
        else:
            # Handle the error if the request fails
            return ({'error': f'Error: {response.status_code} - {response.reason}'}), 500


    def get(self):
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        string_to_sign=f'GET\n\n\n{timestamp}\n/'
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')

        # Create the Authorization header value
        authorization_header = f'AWS {access_key}:{signature}'

        # Construct the headers for the request
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header
        }

        # Send the PUT request to create the bucket
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            # Extract the bucket names from the XML response
            buckets = response.text.split('<Name>')[1:]
            bucket_names = [bucket.split('</Name>')[0] for bucket in buckets]
            return {'buckets': bucket_names}, 200
        else:
            # Handle the error if the request fails
            return f'Error: {response.status_code} - {response.reason}', 500

class BucketsOperation(Resource):
    def get(self, bucket_name):
        url = f'{endpoint}/{bucket_name}'
        timestamp = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        string_to_sign = f'GET\n\n\n{timestamp}\n/{bucket_name}'
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')
        authorization_header = f'AWS {access_key}:{signature}'
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            dict = xmltodict.parse(response.text)
            li = []
            bucket_name = dict['ListBucketResult']['Name']

            # checking for empty bucket
            if dict['ListBucketResult'].get('Contents') is None:
                return {bucket_name: li}

            contents = dict['ListBucketResult'].get('Contents')
            for content in contents:
                key = content.get('Key')
                last_modified = content.get('LastModified')
                ETag=content.get('ETag')
                storgeclass=content.get('StorageClass')
                Type=content.get('Type')
                owner=content.get('Owner')
                size = content.get('Size')
                li.append({'obj_name': key, 'last_modified': last_modified, 'size': size,'ETag':ETag,'StorageClass':storgeclass,'Type':Type,'owner':owner})

            return {bucket_name: li}
        else:
            return f'Error: {response.status_code} - {response.reason}', 500

    def delete(self, bucket_name):
        url = f'{endpoint}/{bucket_name}'
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        string_to_sign = f'DELETE\n\n\n{timestamp}\n/{bucket_name}'
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')
        authorization_header = f'AWS {access_key}:{signature}'
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header
        }
        response = requests.delete(url, headers=headers)
        if response.status_code == 204:
            return ({"massage": f"delete {bucket_name} is secussfully"})
        return ({"massage": 'delete bucket not secceed'})

    def put(self, bucket_name):
        request_data = request.get_json()
        quotes = request_data.get('quotes')
        data = json.dumps(quotes)
        url = f'{endpoint}/{bucket_name}?quota'
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        string_to_sign = f'PUT\n\n\n{timestamp}\n/{bucket_name}?quota'

        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')
        authorization_header = f'AWS {access_key}:{signature}'

        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header,
            'Content-Type': 'application/json'
        }


        response = requests.put(url, headers=headers, data=data)

        if response.status_code == 200:
            return {"message": "Successful"}

        return {"error": response.status_code}


class ObjectInBucket(Resource):
    def put(self,bucket_name,object_name):
        file = request.files.get('file')
        file_data = file.read()
        url = f'{endpoint}/{bucket_name}/{object_name}'
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        string_to_sign = f'PUT\n\nimage/jpeg\n{timestamp}\n/{bucket_name}/{object_name}'
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')
        authorization_header = f'AWS {access_key}:{signature}'
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header,
            'Content-Type':'image/jpeg'
        }
        response = requests.put(url, headers=headers,data=file_data)
        headers['x-amz-acl'] = 'public-read'
        print(response)
        if response.status_code == 200:
             return ({'massage':"Object put successfully."})
        else:
             return(f'Error putting object. Status code: {response.status_code}')

    def delete(self,bucket_name,object_name):
        url = f'{endpoint}/{bucket_name}/{object_name}'
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        string_to_sign = f'DELETE\n\n\n{timestamp}\n/{bucket_name}/{object_name}'
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')
        authorization_header = f'AWS {access_key}:{signature}'
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header,
        }
        response = requests.delete(url, headers=headers)
        if response.status_code == 204:
            return ({'massage': "Object delete successfully."})
        else:
            return (f'Error deleting object. Status code: {response.status_code}')
class BucketACL(Resource):
    def get(self, bucket_name):
        # Configure the AWS S3 endpoint and bucket URL
        url = f'{endpoint}/{bucket_name}/?acl'
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        string_to_sign = f'GET\n\n\n{timestamp}\n/{bucket_name}/?acl'
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')
        authorization_header = f'AWS {access_key}:{signature}'
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header,
        }

        # Make the GET request to retrieve the bucket ACL
        response = requests.get(url,headers=headers)

        if response.status_code == 200:
            acl = response.text
            return {"bucket": bucket_name, "acl": acl}
        else:
            return {"error": "Failed to retrieve bucket ACL"}, response.status_code

class BucketPolicy(Resource):
    def put(self,bucket_name):
        # Configure the AWS S3 endpoint and bucket URL
        request_data=request.get_json()
        user=request_data.get('user')
        url = f'{endpoint}/{bucket_name}/?policy'
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        string_to_sign = f'PUT\n\n\n{timestamp}\n/{bucket_name}/?policy'
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')
        authorization_header = f'AWS {access_key}:{signature}'
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header,
        }
        policy = {
                "Version": "2012-10-17",
                "Id": "S3Policy1",
                "Statement": [
                    {
                        "Sid": "BucketAllow",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": [f"arn:aws:iam:::user/{user}"]
                        },
                        "Action": [
                            "s3:PutObject",
                            "s3:GetObject"
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}",
                            f"arn:aws:s3:::{bucket_name}/*"
                        ]
                    }
                ]
            }
        policy_json = json.dumps(policy)
        # Make the GET request to retrieve the bucket ACL
        response = requests.put(url,headers=headers,data=policy_json)

        if response.status_code == 204:
            print('Bucket policy set successfully.')
        else:
            print(f'Error setting bucket policy. Status code: {response.status_code}',response.text,"jh")

    def get(self, bucket_name):
        # Configure the AWS S3 endpoint and bucket URL
        url = f'{endpoint}/{bucket_name}/?policy'
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        string_to_sign = f'GET\n\n\n{timestamp}\n/{bucket_name}/?policy'
        signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(signature.digest()).decode('utf-8')
        authorization_header = f'AWS {access_key}:{signature}'
        headers = {
            'Host': endpoint,
            'Date': timestamp,
            'Authorization': authorization_header,
        }
        # Make the GET request to retrieve the bucket ACL
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            print('Bucket policy set successfully.')
        else:
            print(f'Error setting bucket policy. Status code: {response.status_code}', response.text, "jh")
api.add_resource(Bucket, '/bucket')
api.add_resource(BucketsOperation,'/buckets/<string:bucket_name>')
api.add_resource(ObjectInBucket,'/buckets/<string:bucket_name>/<string:object_name>')
api.add_resource(BucketACL, "/buckets/<string:bucket_name>/acl")
api.add_resource(BucketPolicy,'/buckets/<string:bucket_name>/policy')


if __name__ == '__main__':
    app.run(debug=True)
