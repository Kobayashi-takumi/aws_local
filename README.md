# aws_local
motoを使用したローカルAWS環境  
アプリケーションはRustで実装している

# 環境
- docker
- docker-compose

# 起動
1. cp .env-sample .env
2. make(upとinitが実行される)
3. cognitoのpool-idとclinet-idを.envにセットする(init時にログに出力される)

# コマンド
- make up
    - コンテナの起動
- make init
    - シードを挿入する
- make down
    - コンテナの削除
- make cli
    - AWS Cliがインストールされているコンテナに入る
- make aws
    - motoのコンテナに入る
- make app
    - Rustのコンテナに入る
- make test
    - Rustのテストコードを実行する

# 環境変数
### ./aws-cli/.env
インフラの環境変数
- AWS_ACCESS_KEY_ID=<ダミーの値>
- AWS_SECRET_ACCESS_KEY=<ダミーの値>
- COGNITO_USER_POOL=<初期値として作成するCognitoのユーザプール名>
- COGNITO_CLIENT_NAME=<初期値として作成するCognitoのクライアント名>
- COGNITO_USER_NAME=<初期値として作成するCognitoのアカウント名>
- USER_EMAIL=<初期値として作成するCognitoのアカウントのemail>
- COGNITO_USER_PASSWORD=<初期値として作成するCognitoのアカウントのパスワード>
- BUCKET_NAME=<初期値として作成するS3のバケット名>
- SES_DOMAIN=<初期値として作成するSESのドメイン名>
### ./.env
アプリケーションの環境変数
- AWS_ACCESS_KEY=<ダミーの値>
- AWS_SERCRET_KEY=<ダミーの値>
- POOL_ID=<init時に出力されるCognitoのpool-id もしくは　AWSで作成したpool-id>
- CLIENT_ID=<init時に出力されるCognitoのclient-id　もしくは　AWSで作成したclient-id>
- REGION=<AWSのリージョン>
- ENDPOINT_URL=http://aws:4000
    - awsコンテナのパス(ローカル以外のAWSを利用する場合は設定しない)
- BUCKET_NAME=<init時に作成したS3のバケット名　もしくは　AWSで作成したバケット名>
- S3_DOMAIN=http://aws:4000
    - awsコンテナのパス(ローカル以外のAWSを利用する場合は正しいS3のDomainにする)
- COGNITO_TEST_EMAIL=<テスト時に作成するユーザのEmail>
- COGNITO_TEST_NEW_EMAIL=<テスト時に更新するユーザのEmail>
- COGNITO_TEST_PASSWORD=<テスト時に作成するユーザのパスワード>