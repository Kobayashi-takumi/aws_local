up:
	docker compose up -d
down:
	docker compose down --rmi all --volumes --remove-orphans
cli:
	docker compose exec cli /bin/bash
init:
	docker compose exec cli /bin/bash -c "chmod a+x ./aws-cli/cognito/init.sh && ./aws-cli/cognito/init.sh"
	docker compose exec cli /bin/bash -c "chmod a+x ./aws-cli/s3/init.sh && ./aws-cli/s3/init.sh"
	docker compose exec cli /bin/bash -c "chmod a+x ./aws-cli/ses/init.sh && ./aws-cli/ses/init.sh"
aws:
	docker compose exec aws /bin/bash
