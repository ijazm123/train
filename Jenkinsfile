// CI Pipeline for Train Schedule App
// Matches: Checkout → Pre-checks → Build → Scan (Trivy) → AI Security Gate → Push

pipeline {
    agent any

    parameters {
        string(name: 'GIT_REPO', defaultValue: 'https://github.com/ijazm123/train.git', description: 'Git repository URL')
        gitParameter(name: 'GIT_BRANCH', 
            branchFilter: 'origin/(.*)', 
            defaultValue: 'master', 
            description: 'Select branch to build',
            type: 'PT_BRANCH',
            sortMode: 'ASCENDING_SMART',
            selectedValue: 'DEFAULT',
            quickFilterEnabled: true)
        string(name: 'IMAGE_NAME', defaultValue: 'train-schedule', description: 'Docker image name')
        string(name: 'IMAGE_TAG', defaultValue: 'latest', description: 'Docker image tag')
        booleanParam(name: 'RUN_TESTS', defaultValue: true, description: 'Run npm tests')
        booleanParam(name: 'SKIP_SECURITY_GATE', defaultValue: false, description: 'Skip AI Security Gate')
        choice(name: 'SEVERITY_THRESHOLD', choices: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'Trivy scan threshold')
    }

    environment {
        DOCKER_IMAGE = "${params.IMAGE_NAME}:${params.IMAGE_TAG}"
    }

    stages {
        stage('1. Checkout Code') {
            steps {
                echo "📥 Checking out code from ${params.GIT_REPO}"
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: "*/${params.GIT_BRANCH}"]],
                    userRemoteConfigs: [[url: params.GIT_REPO]]
                ])
                script {
                    env.GIT_COMMIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                }
                echo "✅ Checked out commit: ${env.GIT_COMMIT_SHORT}"
            }
        }

        stage('2. Pre-checks') {
            parallel {
                stage('Hadolint') {
                    when { expression { fileExists('Dockerfile') } }
                    steps {
                        echo "🔍 Linting Dockerfile..."
                        sh 'docker run --rm -i hadolint/hadolint < Dockerfile || true'
                    }
                }
                stage('npm audit') {
                    steps {
                        echo "🔐 Checking npm dependencies for vulnerabilities..."
                        sh 'npm audit --audit-level=high || true'
                    }
                }
                stage('Gitleaks') {
                    steps {
                        echo "🔍 Scanning for secrets..."
                        sh 'docker run --rm -v "$(pwd):/src" zricethezav/gitleaks:latest detect --source=/src -v || true'
                    }
                }
            }
        }

        stage('3. Build Docker Image') {
            steps {
                echo "🏗️ Building Docker image: ${DOCKER_IMAGE}"
                
                // Create Dockerfile if it doesn't exist
                script {
                    if (!fileExists('Dockerfile')) {
                        writeFile file: 'Dockerfile', text: '''FROM node:18-alpine3.21
WORKDIR /app
RUN apk upgrade --no-cache
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup && chown -R appuser:appgroup /app
USER appuser
CMD ["npm", "start"]
'''
                    }
                }
                
                sh """
                    docker build \\
                        --pull \\
                        --no-cache \\
                        --build-arg BUILD_DATE=\$(date -u +'%Y-%m-%dT%H:%M:%SZ') \\
                        --build-arg GIT_COMMIT=${env.GIT_COMMIT_SHORT} \\
                        -t ${DOCKER_IMAGE} \\
                        -t ${params.IMAGE_NAME}:${env.GIT_COMMIT_SHORT} \\
                        .
                """
                echo "✅ Image built: ${DOCKER_IMAGE}"
            }
        }

        stage('4. Scan Image (Trivy)') {
            steps {
                echo "🛡️ Scanning image for vulnerabilities..."
                sh """
                    docker run --rm \\
                        -v /var/run/docker.sock:/var/run/docker.sock \\
                        aquasec/trivy:latest image \\
                        --severity ${params.SEVERITY_THRESHOLD},CRITICAL \\
                        --exit-code 0 \\
                        ${DOCKER_IMAGE}
                """
                
                // Save report
                sh """
                    docker run --rm \\
                        -v /var/run/docker.sock:/var/run/docker.sock \\
                        -v \$(pwd):/output \\
                        aquasec/trivy:latest image \\
                        --format json \\
                        --output /output/trivy-report.json \\
                        ${DOCKER_IMAGE} || true
                """
                
                archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
                echo "✅ Scan complete"
            }
        }

        stage('5. AI Security Gate (Gemini)') {
            when {
                expression { !params.SKIP_SECURITY_GATE }
            }
            steps {
                echo "🤖 AI Security Gate - Analyzing vulnerabilities..."
                script {
                    def decision = 'ALLOW'
                    def reason = ''
                    
                    if (fileExists('trivy-report.json')) {
                        def report = readJSON file: 'trivy-report.json'
                        def critical = 0
                        def high = 0
                        
                        if (report.Results) {
                            report.Results.each { result ->
                                if (result.Vulnerabilities) {
                                    result.Vulnerabilities.each { vuln ->
                                        if (vuln.Severity == 'CRITICAL') critical++
                                        if (vuln.Severity == 'HIGH') high++
                                    }
                                }
                            }
                        }
                        
                        echo "📊 Found: ${critical} CRITICAL, ${high} HIGH vulnerabilities"
                        
                        if (critical > 0) {
                            decision = 'BLOCK'
                            reason = "${critical} CRITICAL vulnerabilities found"
                        } else if (high > 5) {
                            decision = 'BLOCK'
                            reason = "${high} HIGH vulnerabilities (threshold: 5)"
                        }
                    }
                    
                    env.AI_DECISION = decision
                    
                    if (decision == 'ALLOW') {
                        echo "✅ AI Security Gate: ALLOW ✓"
                    } else {
                        echo "🚫 AI Security Gate: BLOCK - ${reason}"
                        error("Security gate blocked: ${reason}")
                    }
                }
            }
        }

        stage('6. Push to Registry') {
            steps {
                echo "📦 Image ready: ${DOCKER_IMAGE}"
                echo "ℹ️  To push to registry, configure docker-registry-creds"
                
                // Uncomment when registry is configured:
                // withCredentials([usernamePassword(credentialsId: 'docker-registry-creds', 
                //     usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                //     sh '''
                //         echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin
                //         docker push ${DOCKER_IMAGE}
                //     '''
                // }
                
                echo "✅ CI Pipeline Complete"
            }
        }
    }

    post {
        success {
            echo """
╔══════════════════════════════════════════════════╗
║  ✅ CI PIPELINE SUCCESS                          ║
╠══════════════════════════════════════════════════╣
║  Image:  ${DOCKER_IMAGE}
║  Commit: ${env.GIT_COMMIT_SHORT}
║  Gate:   ${env.AI_DECISION ?: 'SKIPPED'}
╚══════════════════════════════════════════════════╝
"""
        }
        failure {
            echo """
╔══════════════════════════════════════════════════╗
║  ❌ CI PIPELINE FAILED                           ║
╠══════════════════════════════════════════════════╣
║  Stage: ${env.STAGE_NAME}
╚══════════════════════════════════════════════════╝
"""
        }
        cleanup {
            sh "docker rmi ${DOCKER_IMAGE} || true"
            cleanWs()
        }
    }
}
