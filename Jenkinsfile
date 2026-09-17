def secrets = [
    [path: params.VAULT_PATH_SVC_ACCOUNT_EPHEMERAL, engineVersion: 1, secretValues: [
        [envVar: 'OC_LOGIN_TOKEN_DEV', vaultKey: 'oc-login-token-dev'],
        [envVar: 'OC_LOGIN_SERVER_DEV', vaultKey: 'oc-login-server-dev']]],
    [path: params.VAULT_PATH_QUAY_PUSH, engineVersion: 1, secretValues: [
        [envVar: 'QUAY_USER', vaultKey: 'user'],
        [envVar: 'QUAY_TOKEN', vaultKey: 'token']]],
    [path: params.VAULT_PATH_RHR_PULL, engineVersion: 1, secretValues: [
        [envVar: 'RH_REGISTRY_USER', vaultKey: 'user'],
        [envVar: 'RH_REGISTRY_TOKEN', vaultKey: 'token']]]
]

def configuration = [vaultUrl: params.VAULT_ADDRESS, vaultCredentialId: params.VAULT_CREDS_ID, engineVersion: 1]

pipeline {
    agent { label 'rhel8' }
    options {
        timestamps()
    }
    environment {
        // --------------------------------------------
        // Options that must be configured by app owner - for the service
        // --------------------------------------------
        APP_NAME="kessel"  // name of app-sre "application" folder this component lives in
        COMPONENT_NAME="parsec"  // name of app-sre "resourceTemplate" in deploy.yaml for this component
        IMAGE="quay.io/cloudservices/kessel-parsec"  // image location on quay
        RUN_PLATSEC=true // optional step to run vulnerability checks
        CICD_URL="https://raw.githubusercontent.com/RedHatInsights/cicd-tools/63daadce8b4b54de5f47747cabf4fdaf6029e272"
        CICD_BOOTSTRAP_SHA256="2fe7070e0ee412756aa1cca3dc4727678c820949d2a95a5214e5a7d99d48df41"
        CICD_COMMIT="63daadce8b4b54de5f47747cabf4fdaf6029e272"
    }
    stages {
        stage('Build the PR commit image') {
            steps {
                withVault([configuration: configuration, vaultSecrets: secrets]) {
                    sh './build_deploy.sh'
                }

                sh 'mkdir -p artifacts'
            }
        }
    }
    post {
        always{
            withVault([configuration: configuration, vaultSecrets: secrets]) {
                sh '''
                    curl -s $CICD_URL/bootstrap.sh > .cicd_bootstrap.sh
                    echo "${CICD_BOOTSTRAP_SHA256}  .cicd_bootstrap.sh" | sha256sum --check --strict
                    source ./.cicd_bootstrap.sh

                    # Pin the second-stage cicd-tools checkout to the immutable commit
                    # so post_test_results.sh comes from the verified revision
                    git -C "$CICD_ROOT" checkout "$CICD_COMMIT" --quiet

                    source "${CICD_ROOT}/post_test_results.sh"
                '''
            }
        }
    }
}
