pipeline{
	agent { node { label 'bionic' } }
	options {
		timeout(time: 1, unit: 'HOURS')
	}
	stages {
		stage ('Checkout') {
			steps {
				checkout scm
			}
		}
		stage ('Install system packages') {
			steps {
				sh "sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq build-essential mtools libssl-dev pkg-config"
				sh "sudo apt-get install -yq flex bison libelf-dev qemu-utils qemu-system libglib2.0-dev libpixman-1-dev libseccomp-dev socat"
				sh "sudo snap install docker"
			}
		}
		stage ('Install Rust') {
			steps {
				sh "nohup curl https://sh.rustup.rs -sSf | sh -s -- -y"
			}
		}
		stage ('Run Cargo tests') {
			steps {
				sh "scripts/run_cargo_tests.sh"
			}
		}
		stage ('Run OpenAPI tests') {
			steps {
				sh "scripts/run_openapi_tests.sh"
			}
		}
		stage ('Run unit tests') {
			steps {
				sh "scripts/run_unit_tests.sh"
			}
		}
		stage ('Run integration tests') {
			steps {
				sh "sudo mount -t tmpfs tmpfs /tmp"
				sh "scripts/run_integration_tests.sh"
			}
		}
	}
}
