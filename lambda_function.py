import boto3
import base64
from botocore.exceptions import ClientError

kms_client = boto3.client('kms')


def lambda_handler(event, context):
    key_id = 'arn:aws:kms:us-east-1:381491837252:key/b1887ad4-f1b5-4483-a633-e09c556f2490'
    
    # Example plaintext data to encrypt
    plaintext = 'Hello, this is a secret message details!'
    
    # Encrypt the data
    encrypted_data = encrypt_data(key_id, plaintext)
    print(f'Encrypted data: {encrypted_data}')
    
    # Decrypt the data
    decrypted_data = decrypt_data(encrypted_data)
    print(f'Decrypted data: {decrypted_data}')
    
    return {
        'statusCode': 200,
        'body': {
            'encrypted_data': encrypted_data,
            'decrypted_data': decrypted_data
        }
    }


def encrypt_data(key_id, plaintext):
    try:
        response = kms_client.encrypt(
            KeyId=key_id,
            Plaintext=plaintext
        )
        ciphertext_blob = response['CiphertextBlob']
        return base64.b64encode(ciphertext_blob).decode('utf-8')
    except ClientError as e:
        print(e)
        return None

def decrypt_data(ciphertext_blob):
    try:
        decoded_blob = base64.b64decode(ciphertext_blob)
        response = kms_client.decrypt(
            CiphertextBlob=decoded_blob
        )
        return response['Plaintext'].decode('utf-8')
    except ClientError as e:
        print(e)
        return None
