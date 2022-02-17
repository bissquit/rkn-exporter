env:
	pip3 install tox pytest pytest-mock pytest-asyncio
	pip3 install --upgrade pip
	pip3 install --no-cache-dir --upgrade -r requirements.txt

test:
	tox -v

start:
	docker-compose up -d --build

stop:
	docker-compose down
