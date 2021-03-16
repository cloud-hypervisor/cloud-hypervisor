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
            		parallel {
				stage ('Worker build') {
					agent { node { label 'groovy' } }
					stages {
						stage ('Checkout') {
							steps {
								checkout scm
							}
						}
						stage ('Run OpenAPI tests') {
							steps {
								sh "scripts/run_openapi_tests.sh"
							}
						}
						stage ('Run unit tests') {
							steps {
								sh "scripts/dev_cli.sh tests --unit"
							}
						}
						stage ('Run integration tests') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration"
							}
						}
					}
				}
				stage ('AArch64 worker build') {
					agent { node { label 'bionic-arm64' } }
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
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration"
							}
						}
					}
					post {
						always {
							sh "sudo chown -R jenkins.jenkins ${WORKSPACE}"
							deleteDir()
						}
					}
				}
				stage ('Worker build (musl)') {
					agent { node { label 'groovy' } }
					stages {
						stage ('Checkout') {
							steps {
								checkout scm
							}
						}
						stage ('Run unit tests for musl') {
							steps {
								sh "scripts/dev_cli.sh tests --unit --libc musl"
							}
						}
						stage ('Run integration tests for musl') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration --libc musl"
							}
						}
					}
				}
				stage ('Worker build SGX') {
					agent { node { label 'bionic-sgx' } }
					when { branch 'master' }
					stages {
						stage ('Checkout') {
							steps {
								checkout scm
							}
						}
						stage ('Run SGX integration tests') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration-sgx"
							}
						}
						stage ('Run SGX integration tests for musl') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration-sgx --libc musl"
							}
						}
					}
					post {
						always {
							sh "sudo chown -R jenkins.jenkins ${WORKSPACE}"
							deleteDir()
						}
					}
				}
				stage ('Worker build VFIO') {
					agent { node { label 'bionic-vfio' } }
					when { branch 'master' }
					stages {
						stage ('Checkout') {
							steps {
								checkout scm
							}
						}
						stage ('Run VFIO integration tests') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration-vfio"
							}
						}
						stage ('Run VFIO integration tests for musl') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration-vfio --libc musl"
							}
						}
					}
					post {
						always {
							sh "sudo chown -R jenkins.jenkins ${WORKSPACE}"
							deleteDir()
						}
					}
				}
				stage ('Worker build - Windows guest') {
					agent { node { label 'groovy-win' } }
					stages {
						stage ('Checkout') {
							steps {
								checkout scm
							}
						}
						stage ('Download assets') {
							steps {
								sh "mkdir ${env.HOME}/workloads"
								azureDownload(storageCredentialId: 'ch-image-store',
											  containerName: 'private-images',
											  includeFilesPattern: 'OVMF-4b47d0c6c8.fd',
											  downloadType: 'container',
											  downloadDirLoc: "${env.HOME}/workloads")
								azureDownload(storageCredentialId: 'ch-image-store',
											  containerName: 'private-images',
											  includeFilesPattern: 'windows-server-2019.raw',
											  downloadType: 'container',
											  downloadDirLoc: "${env.HOME}/workloads")
							}
						}
						stage ('Run Windows guest integration tests') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration-windows"
							}
						}
						stage ('Run Windows guest integration tests for musl') {
							options {
								timeout(time: 1, unit: 'HOURS')
							}
							steps {
								sh "scripts/dev_cli.sh tests --integration-windows --libc musl"
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
				if (env.BRANCH_NAME == 'master') {
					slackSend (color: '#ff0000', message: '"master" branch build is now failing')
				}
			}
		}
		fixed {
			script {
				if (env.BRANCH_NAME == 'master') {
					slackSend (color: '#00ff00', message: '"master" branch build is now fixed')
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
