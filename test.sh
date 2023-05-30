docker build -t docker-port-exporter:local .

docker run -ti --rm \
	-v /var/run/docker.sock:/var/run/docker.sock:ro \
	-e DPE_CONFIG_URL_1=unix:///var/run/docker.sock \
	-p 8931:8931 \
	docker-port-exporter:local
