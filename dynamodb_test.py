#!/usr/bin/env python3
import boto3


def main():
    dynamo = boto3.client('dynamodb')
    result = dynamo.scan(TableName='jtate-dynamo-1')
    items = result['Items']
    for item in items:
        if 'key' in item and 'value' in item:
            print(item['key']['S'] + ':', item['value']['S'])


if __name__ == '__main__':
    main()
