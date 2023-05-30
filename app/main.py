from prometheus_client import start_http_server, Gauge, Enum
import codecs
import docker
import signal
import ssl
import pytz
import yaml
import re
import os
import time
import traceback
from dotenv import load_dotenv, find_dotenv
import datetime

load_dotenv(find_dotenv())


class AppConfig():
	def __init__(self, file: str):
		# set defaults for config from environment variables if they exist
		self.metrics = {
			"port": int(dict_get(os.environ, "DPE_CONFIG_METRICS_PORT", "8931")),
			"pollingInterval": int(dict_get(os.environ, "DPE_CONFIG_METRICS_POLLING_INTERVAL", "60"))
		}
		self.hosts = list()
		self.labels = list()

		try:
			# check if file exists
			if os.path.exists(file):
				print(f"Loading config from {file}")
				with codecs.open(file, encoding="utf-8-sig", mode="r") as f:
					settings = yaml.safe_load(f)
					self.__dict__.update(settings)
		except yaml.YAMLError as exc:
			print(exc)

		env_hosts = self.find_hosts_from_environment()


		# unix://var/run/docker.sock
		if len(env_hosts) > 0:
			# merge env_hosts with config file
			self.hosts = self.hosts + env_hosts
			print(f"Appended {len(env_hosts)} hosts from environment variables")

		env_labels = self.find_labels_from_environment()
		if len(env_labels) > 0:
			# merge env_labels with config file
			for label in env_labels:
				# check if label already exists
				if label['name'] not in [x['name'] for x in self.labels]:
					print(f"adding label {label['name']} from environment variables")
					self.labels.append(label)
			print(f"Appended {len(env_labels)} labels from environment variables")

	def find_labels_from_environment(self):
		labels = list()
		for env in os.environ:
			pattern = r"^DPE_CONFIG_LABEL_([A-Z0-9_-]+)$"
			if re.match(pattern, env, re.IGNORECASE | re.DOTALL):
				print(f"Found Label from Environment Variable: {env}")
				# get the capture group
				label = re.search(pattern, env, re.IGNORECASE | re.DOTALL).group(1)
				# get the value
				value = os.environ[env]
				# add to labels
				labels.append({
					"name": label.lower(),
					"value": value
				})
		return labels

	def find_hosts_from_environment(self): # -> list
		hosts = list()

		for env in os.environ:
			host_id_match = re.match(r"^DPE_CONFIG_URL_(\d{1,})$", env, re.IGNORECASE | re.DOTALL)
			if host_id_match:
				host_id = host_id_match.group(1)
				print(f"Found Host from Environment Variable: {env} = {os.environ[env]}")
				# split value by :
				values = os.environ[env].split(":")
				# check if we have 2 values

				cert = None
				# check if we have a cert path for this host
				if os.environ.get(f"DPE_CONFIG_CERT_PATH_{host_id}", None) is not None:
					cert = os.environ[f"DPE_CONFIG_CERT_PATH_{host_id}"]
					print(f"Found Cert Path for {host_id}: {cert}")

				# check if we have a tls verify for this host
				verify = False
				if os.environ.get(f"DPE_CONFIG_TLS_VERIFY_{host_id}", None) is not None:
					print(f"Found TLS Verify for {host_id}: {os.environ[f'DPE_CONFIG_TLS_VERIFY_{host_id}']}")
					booly = os.environ[f"DPE_CONFIG_TLS_VERIFY_{host_id}"]
					if booly.lower() == "true" or booly.lower() == "1" or booly.lower() == "yes":
						verify = True

				if len(values) >= 2 or len(values) <= 3:
					# add to hosts
					hosts.append({
						"scheme": values[0],
						"name": values[1],
						"port": values[2] if len(values) == 3 else "",
						"cert": cert,
						"verify": verify
					})
				else:
					print(f"Invalid host config for {env} - expected 3 values, got {len(values)} : {os.environ[env]}")
		return hosts

class DockerPortMetrics:
	def __init__(self, config):
		self.namespace = "docker"
		self.polling_interval_seconds = config.metrics['pollingInterval']
		self.config = config
		base_labels = [
			"endpoint",
			"name",
			"id"
		]

		labels = base_labels + [x['name'] for x in self.config.labels]

		port_labels = [
			"public_port",
			"private_port",
			"transport",
		]

		port_labels = port_labels + base_labels
		volume_labels = [
			"source",
			"destination",
			"mode"
		]
		volume_labels = volume_labels + base_labels

		self.ports = Gauge(namespace=self.namespace, name=f"port", documentation="", labelnames=port_labels)
		self.volumes = Gauge(namespace=self.namespace, name=f"volume", documentation="", labelnames=volume_labels)

	def run_metrics_loop(self):
		"""Metrics fetching loop"""
		while True:
			print(f"begin metrics fetch")
			self.fetch()
			time.sleep(self.polling_interval_seconds)


	def fetch(self):
		hosts = self.config.hosts
		error_count = 0
		# loop hosts
		print(f"found {len(hosts)} hosts")

		for host in hosts:
			try:
				if host['scheme'] is None or host['scheme'] == "unix":
					if host['port'] is not None and host['port'] != "":
						host['port'] = ""
				elif host['scheme'] != "tcp":
					if host['port'] is None or host['port'] != "2375":
						host['port'] = f":{host['port']}"

				if host['port'] is not None and host['port'] != "":
					host['port'] = f":{host['port'].replace(':', '')}"


				print(f"fetching metrics from {host['scheme']}:{host['name']}{host['port']}")

				client = docker.APIClient(
					base_url=f"{host['scheme']}:{host['name']}{host['port']}",
					# cert=f"{host['cert']}" if host['cert'] is not None else None,
					tls=host['verify'] if host['cert'] is not None else False,
					)
				# get containers
				containers = client.containers(all=True, filters={"status": "running"})
				# loop containers
				# only get running containers
				for container in containers:
					for port in [p for p in container['Ports'] if "IP" not in p or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", p['IP']) is not None]:
						port_labels = {
							"endpoint": f"{host['scheme']}:{host['name']}{host['port']}",
							"name": container['Names'][0].replace('/', ''),
							"id": container['Id'],
							"public_port": port['PublicPort'] if "PublicPort" in port else port['PrivatePort'],
							"private_port": port['PrivatePort'],
							"transport": port['Type']
						}

						self.ports.labels(**port_labels).set(1)

					for volume in [m for m in container['Mounts'] if m['Type'] == "bind"]:
						volume_labels = {
							"endpoint": f"{host['scheme']}:{host['name']}{host['port']}",
							"name": container['Names'][0].replace('/', ''),
							"id": container['Id'],
							"source": volume['Source'],
							"destination": volume['Destination'],
							"mode": volume['Mode']
						}
						self.volumes.labels(**volume_labels).set(1)

			except Exception as e:
				error_count += 1
				print(f"Error fetching metrics from {host['scheme']}:{host['name']}{host['port']}")
				traceback.print_exc()
		print(f"end metrics fetch")

def dict_get(dictionary, key, default_value = None):
	if key in dictionary.keys():
		return dictionary[key] or default_value
	else:
		return default_value

def sighandler(signum, frame):
	print("<SIGTERM received>")
	exit(0)

def main():
	signal.signal(signal.SIGTERM, sighandler)

	try:
		config_file = dict_get(os.environ, "DPE_CONFIG_FILE", default_value="./config/.configuration.yaml")

		config = AppConfig(config_file)

		print(f"start listening on :{config.metrics['port']}")
		app_metrics = DockerPortMetrics(config)
		start_http_server(config.metrics['port'])
		app_metrics.run_metrics_loop()
	except KeyboardInterrupt:
		exit(0)

if __name__ == "__main__":
	main()
