env:
	pip3 install tox pytest pytest-mock pytest-asyncio k8s-handle
	pip3 uninstall -y markupsafe && pip install markupsafe==2.0.1
	pip3 install --upgrade pip
	pip3 install --no-cache-dir --upgrade -r requirements.txt

test:
	tox -v

start:
	docker-compose up -d --build

stop:
	docker-compose down
