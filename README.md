# dumb-lambda-basicauth-site

This is a simple flask app to give you a static site wrapped with basicauth protection.

> "dumb" because we shouldn't be serving static files through flask... but it's easy

## Configurable Environment Variables

- BASIC_AUTH_USERNAME 
- BASIC_AUTH_PASSWORD
- SITE_DIRECTORY_RELPATH


## Deploy your site

1. Copy assets to ./site (html, css, etc)

2. create your zappa config:

    ```json
    {
        "dev": {
            "app_function": "app.app",
            "aws_region": "ap-northeast-1",
            "profile_name": "YOUR_PROFILE",
            "project_name": "dumb-lambda-bas",
            "runtime": "python3.6",
            "s3_bucket": "zappa-YOURBUCKET",
            "environment_variables": {
                "BASIC_AUTH_USERNAME": "YOUR_USERNAME",
                "BASIC_AUTH_PASSWORD": "YOUR_PASSWORD"
            }
        }
    }
    ```
    
3. Deploy


4. Integrate Basic Auth for APIGateway...

    > To enable basic auth to be handled properly by APIGateway some steps are needed...