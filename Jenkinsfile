stage ("Builds") {
	node ('bionic') {
		stage ('Checkout') {
			checkout scm
		}
		stage ('Install system packages') {
			sh "sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq build-essential mtools libssl-dev pkg-config"
			sh "sudo apt-get install -yq flex bison libelf-dev qemu-utils qemu-system libglib2.0-dev libpixman-1-dev libseccomp-dev"
		}
		stage ('Install Rust') {
			sh "nohup curl https://sh.rustup.rs -sSf | sh -s -- -y"
		}
		stage ('Run unit tests') {
			sh "sudo chmod a+rw /dev/kvm"
			sh "scripts/run_unit_tests.sh"
		}
		stage ('Run integration tests') {
                        sh "sudo mount -t tmpfs tmpfs /tmp"
			sh "scripts/run_integration_tests.sh"
		}
	}
}

