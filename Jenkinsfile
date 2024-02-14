def runWorkers = true
pipeline {
    agent none
    options {
        timeout(time: 4, unit: 'HOURS')
    }
    stages {
        stage('Early checks') {
            agent { node { label 'built-in' } }
            stages {
                stage('Checkout') {
                    steps {
                        checkout scm
                    }
                }
                stage('Check if worker build can be skipped') {
                    when {
                        expression {
                            return skipWorkerBuild()
                        }
                    }
                    steps {
                        script {
                            runWorkers = false
                            echo 'No changes requiring a build'
                        }
                    }
                }
                stage('Check for RFC/WIP builds') {
                    when {
                        changeRequest comparator: 'REGEXP', title: '.*(rfc|RFC|wip|WIP).*'
                        beforeAgent true
                    }
                    steps {
                        error('Failing as this is marked as a WIP or RFC PR.')
                    }
                }
                stage('Cancel older builds') {
                    when { not { branch 'main' } }
                    steps {
                        cancelPreviousBuilds()
                    }
                }
            }
        }
        stage('Build') {
            parallel {
                stage('Worker build') {
                    agent { node { label 'jammy-ch' } }
                    when {
                        beforeAgent true
                        expression {
                            return runWorkers
                        }
                    }
                    environment {
                        AUTH_DOWNLOAD_TOKEN = credentials('8a26fd74-d40e-414c-9132-ff3f867806ef')
                    }
                    stages {
                        stage('Checkout') {
                            steps {
                                checkout scm
                            }
                        }
                        stage('Prepare environment') {
                            steps {
                                sh 'scripts/prepare_vdpa.sh'
                            }
                        }
                        stage('Run unit tests') {
                            steps {
                                sh 'scripts/dev_cli.sh tests --unit'
                            }
                        }
                        stage('Run integration tests') {
                            options {
                                timeout(time: 1, unit: 'HOURS')
                            }
                            steps {
                                sh 'sudo modprobe openvswitch'
                                sh 'scripts/dev_cli.sh tests --integration'
                            }
                        }
                        stage('Run live-migration integration tests') {
                            options {
                                timeout(time: 1, unit: 'HOURS')
                            }
                            steps {
                                sh 'sudo modprobe openvswitch'
                                sh 'scripts/dev_cli.sh tests --integration-live-migration'
                            }
                        }
                        stage('Run unit tests for musl') {
                            steps {
                                sh 'scripts/dev_cli.sh tests --unit --libc musl'
                            }
                        }
                        stage('Run integration tests for musl') {
                            options {
                                timeout(time: 1, unit: 'HOURS')
                            }
                            steps {
                                sh 'sudo modprobe openvswitch'
                                sh 'scripts/dev_cli.sh tests --integration --libc musl'
                            }
                        }
                        stage('Run live-migration integration tests for musl') {
                            options {
                                timeout(time: 1, unit: 'HOURS')
                            }
                            steps {
                                sh 'sudo modprobe openvswitch'
                                sh 'scripts/dev_cli.sh tests --integration-live-migration --libc musl'
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
                    slackSend(color: '#ff0000', message: '"main" branch build is now failing', channel: '#jenkins-ci')
                }
            }
        }
        fixed {
            script {
                if (env.BRANCH_NAME == 'main') {
                    slackSend(color: '#00ff00', message: '"main" branch build is now fixed', channel: '#jenkins-ci')
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

def installAzureCli(distro, arch) {
    sh 'sudo apt install -y ca-certificates curl apt-transport-https lsb-release gnupg'
    sh 'curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null'
    sh "echo \"deb [arch=${arch}] https://packages.microsoft.com/repos/azure-cli/ ${distro} main\" | sudo tee /etc/apt/sources.list.d/azure-cli.list"
    sh 'sudo apt update'
    sh 'sudo apt install -y azure-cli'
}

def boolean skipWorkerBuild() {
    if (env.CHANGE_TARGET == null) {
        return false
    }

    if (sh(
        returnStatus: true,
        script: "git diff --name-only origin/${env.CHANGE_TARGET}... | grep -v '\\.md'"
    ) != 0) {
        return true
    }

    if (sh(
        returnStatus: true,
        script: "git diff --name-only origin/${env.CHANGE_TARGET}... | grep -v -E 'fuzz/'"
    ) != 0) {
        return true
    }

    if (sh(
        returnStatus: true,
        script: "git diff --name-only origin/${env.CHANGE_TARGET}... | grep -v -E '.github/'"
    ) != 0) {
        return true
    }

    if (sh(
        returnStatus: true,
        script: "git diff --name-only origin/${env.CHANGE_TARGET}... | grep -v '^\\.'"
    ) != 0) {
        return true
    }

    if (sh(
        returnStatus: true,
        script: "git diff --name-only origin/${env.CHANGE_TARGET}... | grep -v 'gitlint'"
    ) != 0) {
        return true
    }

    return false
}
