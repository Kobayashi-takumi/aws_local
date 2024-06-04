#!/bin/bash
aws s3 mb --endpoint-url ${AWS_URL} s3://${BUCKET_NAME}
aws s3 cp ./aws-cli/s3/Arch_Amazon-Simple-Storage-Service_48.png s3://${BUCKET_NAME}/s3-icon.png --endpoint-url ${AWS_URL} --acl public-read-write
echo "S3 Script completed."
