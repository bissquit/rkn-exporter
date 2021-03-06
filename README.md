# Prometheus exporter developed to indicate what your domains are blocked by Roskomnadzor agency to access from Russia

Exporter receives as input data (both are mandatory):

 - blocked ips list provided by url with json (I recommend to use https://reestr.rublacklist.net/api/v2/ips/json/) or text file (each line is either ip or ip subnet);
 - a list of your domains which need to check.

As output data exporter provides metrics to be scraped by Prometheus. Three metrics per domain and one metric for computation process. For example:

```text
rkn_resolved_ip_count{domain_name="subdomain.domain.tld"} 4
rkn_resolved_ip_blocked_count{domain_name="subdomain.domain.tld"} 1
rkn_resolved_ip_blocked{domain_name="subdomain.domain.tld",ip="1.2.3.4"} 0
rkn_resolved_ip_blocked{domain_name="subdomain.domain.tld",ip="1.2.3.5"} 0
rkn_resolved_ip_blocked{domain_name="subdomain.domain.tld",ip="1.2.3.6"} 1
rkn_resolved_ip_blocked{domain_name="subdomain.domain.tld",ip="1.2.3.7"} 0
rkn_resolved_success{domain_name="subdomain.domain.tld"} 1

rkn_computation_success 1
```

Metrics descriptions:

|Metric name|Description|Note|
| ----------- | ----------- | ----------- |
|`rkn_resolved_ip_count`|Number of ip addresses that domain is resolving in||
|`rkn_resolved_ip_blocked_count`|Number of ip addresses that are blocked by RKN agency to access from Russia||
|`rkn_resolved_ip_blocked`|IP address is blocked (True/False)|Only available with `--ip_in_label` option. Be careful! Read more about this feature below|
|`rkn_resolved_success`|Domain name successfully resolved (True/False)||
|`rkn_computation_success`|Metric computation success (True/False)||

Metrics are available at `/metrics` path.

## Usage

Multiple installation scenarios are provided. You should create input files. For test purposes run the following commands first and proceed:

```text
mkdir inputs
echo google.com > inputs/domains.txt
echo 142.251.0.0/16 > inputs/blocked_subnets.txt
```

### Docker

Run:

```shell script
PORT=8080 ; docker run -it --rm --name rkn-exporter \
  -p ${PORT}:${PORT} \
  -v "$(pwd)/inputs":"/app/inputs" \
  -e APP_IP=0.0.0.0 \
  -e APP_PORT=${PORT} \
  -e APP_CHECK_INTERVAL=3600 \
  -e APP_DOMAINS=/app/inputs/domains.txt \
  -e APP_SUBNETS=/app/inputs/blocked_subnets.txt \
  -e APP_THREADS_COUNT=10 \
  -e APP_DNS=8.8.8.8 \
  -e LOG_LEVEL=DEBUG \
  bissquit/rkn-exporter:latest \
    "python3" \
    "rkn_exporter.py" \
    "--ip_in_label"
```

### Docker-compose

For testing purposes or for quick review you may use Docker Compose:

```shell script
docker-compose up -d --build --force-recreate
```

### k8s

Use [k8s-handle](https://github.com/2gis/k8s-handle) to deploy exporter to k8s environment:

```shell script
cd kubernetes

k8s-handle apply -s env-name
```

Render templates without deployment:

```shell script
k8s-handle render -s env-name
```
---
**Note**: if you have the following error with k8s-handle and Python 3.8 and later:
```text
ImportError: cannot import name 'soft_unicode' from 'markupsafe'
```
Run the command below:
```shell script
pip uninstall -y markupsafe && pip install markupsafe==2.0.1
```
This command is not needed if you configure env with `make env`.

## Help

|Command line argument|Environment variable|Description|
| ----------- | ----------- | ----------- |
|`-h`, `--help`|-|show help message|
|`-i`, `--ip`|`APP_IP`|IP address (default: 0.0.0.0)|
|`-p`, `--port`|`APP_PORT`|Port to be listened (default: 8080)|
|`-c`, `--check_interval`|`APP_CHECK_INTERVAL`|Default time range in seconds to check metrics (default: 3600)|
|`-d`, `--domains`|`APP_DOMAINS`|Path to a file with domains to check. One domain per line (default: No)|
|`-s`, `--blocked_subnets`|`APP_SUBNETS`|Path to a file with subnets bloked by RKN. One subnet per line. Or url with json list (default: No)|
|`-t`, `--threads_count`|`APP_THREADS_COUNT`|Threads count to parallelize computation. Is useful when DNS resolving is slow (default: 10)|
|`--dns`|`APP_DNS`|DNS servers (default: 8.8.8.8)|
|`--ip_in_label`|-|Enable putting ip into labels. Not recommended! (default: False) Read more about this feature below|
|-|`LOG_LEVEL`|Log level based on Python [logging](https://docs.python.org/3/library/logging.html) module. expected values: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)|

**Note:** `--ip_in_label` is experimental feature. Don't use it in production because it extremely increases cardinality: each uniq set of metrics and their labels produce a time series. Because you have potentially unlimited amount of IP addresses you'll receive coresponding amount of time series. Read more at [Cardinality is key](https://www.robustperception.io/cardinality-is-key) article.

## Dev environment

Setup environment is quite simple:
```shell script
make env
make test
```
**Note:** tox will install his own environments. You may add it as interpreter in your IDE - `./tox/py39/bin/python`

To use Python venv execute the following commands:
```shell script
mkdir venv
python3 -m venv venv
. venv/bin/activate

make env
make test
```
To deactivate venv from current shell session run:
```shell script
deactivate
```

### How to start

```bash
make start
```
