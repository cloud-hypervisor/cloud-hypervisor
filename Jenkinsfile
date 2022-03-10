def runWorkers = true
pipeline{
	agent none
	stages {
		stage ('Early checks') {
			agent { node { label 'built-in' } }
			stages {
				stage ('Checkout') {
					steps {
						checkout scm
					}
				}
				stage ('Check for documentation only changes') {
					when {
						expression {
							return docsFileOnly()
						}
					}
					steps {
						script {
							runWorkers = false
							echo "Documentation only changes, no need to run the CI"
						}
					}
				}
				stage ('Check for RFC/WIP builds') {
					when {
  						changeRequest comparator: 'REGEXP', title: '.*(rfc|RFC|wip|WIP).*'
  						beforeAgent true
					}
					steps {
						error("Failing as this is marked as a WIP or RFC PR.")
					}
				}
				stage ('Cancel older builds') {
					when { not { branch 'main' } }
					steps {
						cancelPreviousBuilds()
					}
				}
			}
		}
		stage ('Build') {
			parallel {
				stage ('Worker build - Metrics') {
					agent { node { label 'focal-metrics-test' } }
					when {
						beforeAgent true
						expression {
							return runWorkers
						}
					}
					environment {
						METRICS_PUBLISH_KEY = credentials('52e0945f-ce7a-43d1-87af-67d1d87cc40f')
					}
					stages {
						stage ('Checkout') {
							steps {
								checkout scm
							}
						}
						stage ('Run metrics tests') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh 'scripts/dev_cli.sh tests --metrics'
							}
						}
					}
				}
			}
		}
	}
	post {
		regression {
			script {
				if (env.BRANCH_NAME == 'main') {
					slackSend (color: '#ff0000', message: '"main" branch build is now failing')
				}
			}
		}
		fixed {
			script {
				if (env.BRANCH_NAME == 'main') {
					slackSend (color: '#00ff00', message: '"main" branch build is now fixed')
				}
			}
		}
	}
}

def cancelPreviousBuilds() {
	// Check for other instances of this particular build, cancel any that are older than the current one
	def jobName = env.JOB_NAME
		def currentBuildNumber = env.BUILD_NUMBER.toInteger()
		def currentJob = Jenkins.instance.getItemByFullName(jobName)

		// Loop through all instances of this particular job/branch
		for (def build : currentJob.builds) {
			if (build.isBuilding() && (build.number.toInteger() < currentBuildNumber)) {
				echo "Older build still queued. Sending kill signal to build number: ${build.number}"
				build.doStop()
			}
		}
}

def installAzureCli() {
	sh "sudo apt install -y ca-certificates curl apt-transport-https lsb-release gnupg"
	sh "curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null"
	sh "echo \"deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ hirsute main\" | sudo tee /etc/apt/sources.list.d/azure-cli.list"
	sh "sudo apt update"
	sh "sudo apt install -y azure-cli"
}

def boolean docsFileOnly() {
    if (env.CHANGE_TARGET == null) {
        return false;
    }

    return sh(
        returnStatus: true,
        script: "git diff --name-only origin/${env.CHANGE_TARGET}... | grep -v '\\.md'"
    ) != 0
}
