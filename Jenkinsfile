pipeline{
	agent none
	stages {
		stage ('Early checks') {
			agent { node { label 'master' } }
			stages {
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
					when { not { branch 'master' } }
					steps {
						cancelPreviousBuilds()
					}
				}
			}
		}
		stage ('Build') {
			failFast true
            parallel {
				stage ('Master build') {
					agent { node { label 'master' } }
					stages {
						stage ('Checkout') {
							steps {
								checkout scm
							}
						}
						stage ('Run Cargo tests') {
							steps {
								sh "scripts/dev_cli.sh tests --cargo"
							}
						}
						stage ('Run OpenAPI tests') {
							steps {
								sh "scripts/run_openapi_tests.sh"
							}
						}
					}
				}	
				stage ('Worker build') {
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
						stage ('Run unit tests') {
							steps {
								sh "scripts/dev_cli.sh tests --unit"
							}
						}
						stage ('Run integration tests') {
							steps {
								sh "scripts/dev_cli.sh tests --integration"
							}
						}
					}
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