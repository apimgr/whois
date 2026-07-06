pipeline {
    agent none

    triggers {
        // Daily build at 3am UTC (matches GitHub Actions daily.yml)
        cron('0 3 * * *')
    }

    environment {
        PROJECTNAME = 'whois'
        PROJECTORG = 'apimgr'
        INTERNAL_NAME = 'caswhois'
        BINDIR = 'binaries'
        RELDIR = 'releases'

        // GIT PROVIDER CONFIGURATION
        // Uncomment ONE block below based on your git hosting platform

        // ----- GITHUB (default) -----
        GIT_FQDN = 'github.com'
        GIT_TOKEN = credentials('github-token')
        REGISTRY = "ghcr.io/${PROJECTORG}/${INTERNAL_NAME}"

        // ----- GITEA / FORGEJO (self-hosted) -----
        // GIT_FQDN = 'git.example.com'
        // GIT_TOKEN = credentials('gitea-token')
        // REGISTRY = "${GIT_FQDN}/${PROJECTORG}/${INTERNAL_NAME}"

        // ----- GITLAB (gitlab.com or self-hosted) -----
        // GIT_FQDN = 'gitlab.com'
        // GIT_TOKEN = credentials('gitlab-token')
        // REGISTRY = "registry.${GIT_FQDN}/${PROJECTORG}/${INTERNAL_NAME}"
    }

    stages {
        stage('Setup') {
            agent { label 'amd64' }
            steps {
                script {
                    // Determine build type and version
                    if (env.TAG_NAME) {
                        // Release build (tag push) - matches release.yml
                        env.BUILD_TYPE = 'release'
                        env.VERSION = env.TAG_NAME.replaceAll('^v', '')
                    } else if (env.BRANCH_NAME == 'beta') {
                        // Beta branch build - matches beta.yml
                        env.BUILD_TYPE = 'beta'
                        env.VERSION = "beta-${env.GIT_COMMIT.take(8)}"
                    } else {
                        // Daily build (main/master or scheduled) - matches daily.yml
                        env.BUILD_TYPE = 'daily'
                        env.VERSION = sh(script: "cat release.txt 2>/dev/null || echo 'devel'", returnStdout: true).trim()
                    }

                    // Set build metadata
                    env.COMMIT_ID = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    env.BUILD_DATE = sh(script: 'date -u +"%a %b %d, %Y at %H:%M:%S UTC"', returnStdout: true).trim()
                    env.LDFLAGS = "-s -w -X 'main.Version=${env.VERSION}' -X 'main.CommitID=${env.COMMIT_ID}' -X 'main.BuildDate=${env.BUILD_DATE}' -X 'main.OfficialSite=https://caswhois.apimgr.dev'"

                    // Check for CLI source
                    env.HAS_CLI = sh(script: 'test -d src/client && echo true || echo false', returnStdout: true).trim()
                }
            }
        }

        stage('Build Server') {
            parallel {
                stage('Linux AMD64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            mkdir -p ${BINDIR}
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=linux \
                                -e GOARCH=amd64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-linux-amd64 ./src
                        '''
                    }
                }
                stage('Linux ARM64') {
                    agent { label 'arm64' }
                    steps {
                        sh '''
                            mkdir -p ${BINDIR}
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=linux \
                                -e GOARCH=arm64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-linux-arm64 ./src
                        '''
                    }
                }
                stage('Darwin AMD64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            mkdir -p ${BINDIR}
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=darwin \
                                -e GOARCH=amd64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-darwin-amd64 ./src
                        '''
                    }
                }
                stage('Darwin ARM64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            mkdir -p ${BINDIR}
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=darwin \
                                -e GOARCH=arm64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-darwin-arm64 ./src
                        '''
                    }
                }
                stage('Windows AMD64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            mkdir -p ${BINDIR}
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=windows \
                                -e GOARCH=amd64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-windows-amd64.exe ./src
                        '''
                    }
                }
                stage('Windows ARM64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            mkdir -p ${BINDIR}
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=windows \
                                -e GOARCH=arm64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-windows-arm64.exe ./src
                        '''
                    }
                }
                stage('FreeBSD AMD64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            mkdir -p ${BINDIR}
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=freebsd \
                                -e GOARCH=amd64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-freebsd-amd64 ./src
                        '''
                    }
                }
                stage('FreeBSD ARM64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            mkdir -p ${BINDIR}
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=freebsd \
                                -e GOARCH=arm64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-freebsd-arm64 ./src
                        '''
                    }
                }
            }
        }

        stage('Build CLI') {
            when {
                expression { env.HAS_CLI == 'true' }
            }
            parallel {
                stage('CLI Linux AMD64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=linux \
                                -e GOARCH=amd64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-cli-linux-amd64 ./src/client
                        '''
                    }
                }
                stage('CLI Linux ARM64') {
                    agent { label 'arm64' }
                    steps {
                        sh '''
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=linux \
                                -e GOARCH=arm64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-cli-linux-arm64 ./src/client
                        '''
                    }
                }
                stage('CLI Darwin AMD64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=darwin \
                                -e GOARCH=amd64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-cli-darwin-amd64 ./src/client
                        '''
                    }
                }
                stage('CLI Darwin ARM64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=darwin \
                                -e GOARCH=arm64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-cli-darwin-arm64 ./src/client
                        '''
                    }
                }
                stage('CLI Windows AMD64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=windows \
                                -e GOARCH=amd64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-cli-windows-amd64.exe ./src/client
                        '''
                    }
                }
                stage('CLI Windows ARM64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=windows \
                                -e GOARCH=arm64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-cli-windows-arm64.exe ./src/client
                        '''
                    }
                }
                stage('CLI FreeBSD AMD64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=freebsd \
                                -e GOARCH=amd64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-cli-freebsd-amd64 ./src/client
                        '''
                    }
                }
                stage('CLI FreeBSD ARM64') {
                    agent { label 'amd64' }
                    steps {
                        sh '''
                            docker run --rm \
                                --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                                -v ${WORKSPACE}:/app \
                                -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                                -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                                -w /app \
                                -e CGO_ENABLED=0 \
                                -e GOOS=freebsd \
                                -e GOARCH=arm64 \
                                casjaysdev/go:latest \
                                go build -buildvcs=false -trimpath -ldflags "${LDFLAGS}" -o ${BINDIR}/${INTERNAL_NAME}-cli-freebsd-arm64 ./src/client
                        '''
                    }
                }
            }
        }

        stage('Test') {
            agent { label 'amd64' }
            steps {
                sh '''
                    docker run --rm \
                        --name "${INTERNAL_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
                        -v ${WORKSPACE}:/app \
                        -v ${GO_CACHE:-$HOME/go/pkg/mod}:/usr/local/share/go/pkg/mod \
                        -v ${GO_BUILD:-$HOME/.cache/go-build/${INTERNAL_NAME}}:/usr/local/share/go/cache \
                        -w /app \
                        casjaysdev/go:latest \
                        go test -v -cover ./...
                '''
            }
        }

        stage('Release: Stable') {
            agent { label 'amd64' }
            when {
                expression { env.BUILD_TYPE == 'release' }
            }
            steps {
                sh '''
                    mkdir -p ${RELDIR}
                    echo "${VERSION}" > ${RELDIR}/version.txt

                    for f in ${BINDIR}/${INTERNAL_NAME}-*; do
                        [ -f "$f" ] || continue
                        cp "$f" ${RELDIR}/
                    done

                    tar --exclude='.git' --exclude='.github' --exclude='.gitea' \
                        --exclude='.forgejo' --exclude='binaries' --exclude='releases' \
                        --exclude='*.tar.gz' \
                        -czf ${RELDIR}/${INTERNAL_NAME}-${VERSION}-source.tar.gz .
                '''
                archiveArtifacts artifacts: 'releases/*', fingerprint: true
            }
        }

        stage('Release: Beta') {
            agent { label 'amd64' }
            when {
                expression { env.BUILD_TYPE == 'beta' }
            }
            steps {
                sh '''
                    mkdir -p ${RELDIR}
                    echo "${VERSION}" > ${RELDIR}/version.txt

                    for f in ${BINDIR}/${INTERNAL_NAME}-*; do
                        [ -f "$f" ] || continue
                        cp "$f" ${RELDIR}/
                    done
                '''
                archiveArtifacts artifacts: 'releases/*', fingerprint: true
            }
        }

        stage('Release: Daily') {
            agent { label 'amd64' }
            when {
                expression { env.BUILD_TYPE == 'daily' }
            }
            steps {
                sh '''
                    mkdir -p ${RELDIR}
                    echo "${VERSION}" > ${RELDIR}/version.txt

                    for f in ${BINDIR}/${INTERNAL_NAME}-*; do
                        [ -f "$f" ] || continue
                        cp "$f" ${RELDIR}/
                    done
                '''
                archiveArtifacts artifacts: 'releases/*', fingerprint: true
            }
        }

        stage('Docker') {
            agent { label 'amd64' }
            steps {
                script {
                    def tags = "-t ${REGISTRY}:${env.COMMIT_ID}"

                    if (env.BUILD_TYPE == 'release') {
                        def yymm = new Date().format('yyMM')
                        tags += " -t ${REGISTRY}:${env.VERSION}"
                        tags += " -t ${REGISTRY}:latest"
                        tags += " -t ${REGISTRY}:${yymm}"
                    } else if (env.BUILD_TYPE == 'beta') {
                        tags += " -t ${REGISTRY}:beta"
                        tags += " -t ${REGISTRY}:devel"
                    } else {
                        tags += " -t ${REGISTRY}:devel"
                    }

                    sh """
                        echo "\${GIT_TOKEN}" | docker login ${REGISTRY.split('/')[0]} -u ${PROJECTORG} --password-stdin
                    """

                    sh """
                        docker buildx create --name ${INTERNAL_NAME}-builder --use 2>/dev/null || docker buildx use ${INTERNAL_NAME}-builder
                        docker buildx build \
                            -f docker/Dockerfile \
                            --platform linux/amd64,linux/arm64 \
                            --build-arg VERSION="${env.VERSION}" \
                            --build-arg COMMIT_ID="${env.COMMIT_ID}" \
                            --build-arg BUILD_DATE="${env.BUILD_DATE}" \
                            --label "org.opencontainers.image.vendor=${PROJECTORG}" \
                            --label "org.opencontainers.image.authors=${PROJECTORG}" \
                            --label "org.opencontainers.image.title=${INTERNAL_NAME}" \
                            --label "org.opencontainers.image.base.name=${INTERNAL_NAME}" \
                            --label "org.opencontainers.image.description=caswhois - self-hosted WHOIS lookup service" \
                            --label "org.opencontainers.image.licenses=MIT" \
                            --label "org.opencontainers.image.version=${env.VERSION}" \
                            --label "org.opencontainers.image.created=${env.BUILD_DATE}" \
                            --label "org.opencontainers.image.revision=${env.COMMIT_ID}" \
                            --label "org.opencontainers.image.url=https://${GIT_FQDN}/${PROJECTORG}/whois" \
                            --label "org.opencontainers.image.source=https://${GIT_FQDN}/${PROJECTORG}/whois" \
                            --label "org.opencontainers.image.documentation=https://${GIT_FQDN}/${PROJECTORG}/whois" \
                            --annotation "manifest:org.opencontainers.image.vendor=${PROJECTORG}" \
                            --annotation "manifest:org.opencontainers.image.authors=${PROJECTORG}" \
                            --annotation "manifest:org.opencontainers.image.title=${INTERNAL_NAME}" \
                            --annotation "manifest:org.opencontainers.image.licenses=MIT" \
                            --annotation "manifest:org.opencontainers.image.version=${env.VERSION}" \
                            --annotation "manifest:org.opencontainers.image.created=${env.BUILD_DATE}" \
                            --annotation "manifest:org.opencontainers.image.revision=${env.COMMIT_ID}" \
                            --annotation "manifest:org.opencontainers.image.url=https://${GIT_FQDN}/${PROJECTORG}/whois" \
                            --annotation "manifest:org.opencontainers.image.source=https://${GIT_FQDN}/${PROJECTORG}/whois" \
                            ${tags} \
                            --push \
                            .
                    """
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
