.DEFAULT_GOAL := init

up:
	docker compose up -d
init: up
	docker compose exec cli /bin/bash -c "chmod a+x ./aws-cli/cognito/init.sh && ./aws-cli/cognito/init.sh"
	docker compose exec cli /bin/bash -c "chmod a+x ./aws-cli/s3/init.sh && ./aws-cli/s3/init.sh"
	docker compose exec cli /bin/bash -c "chmod a+x ./aws-cli/ses/init.sh && ./aws-cli/ses/init.sh"
down:
	docker compose down --rmi all --volumes --remove-orphans
cli:
	docker compose exec cli /bin/bash
aws:
	docker compose exec aws /bin/bash
app:
	docker compose exec aws_app bash
test:
	docker compose run --rm aws_app sh -c "RUST_LOG=debug cargo test --all"

