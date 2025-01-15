import {useAuth} from "react-oidc-context"
import {createManagedAuthAdapter, createStorageBrowser,} from '@aws-amplify/ui-react-storage/browser';
import {Button, Flex, Heading, View} from "@aws-amplify/ui-react";
import './App.css'
import '@aws-amplify/ui-react/styles.css'


function App() {
    const auth = useAuth()
    const clientId = "2b7c4fc8-2f89-45e1-b537-06de31fd03c5"
    const logoutUri = "http://localhost:5173/"
    const idpUrl = "https://login.microsoftonline.com/e0916847-79ae-4d02-9184-ba50443a043d/oauth2/v2.0"
    const scope = "email openid profile api://2b7c4fc8-2f89-45e1-b537-06de31fd03c5/S3AG"

    async function getNewToken(){
        // Some SDK do not refresh tokens unless they are about to expire.
        // To use Identity Center Trusted Identity Propagation you need to request credentials using a never used token
        // This function get a new token but do not refresh the session.
        const tokenUrl = `${idpUrl}/token`
        try {
            const params = new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: clientId,
                refresh_token: auth.user.refresh_token,
                scope: scope
            }), new_tokens = await fetch(tokenUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': window.location.origin
                },
                body: params
            },);
            return await new_tokens.json()
        } catch(e) {
            console.log(e)
            throw e
        }
    }
    async function fetchCredentials() {
        const FetchCredentialsUrl = 'https://37dd795ndj.execute-api.us-east-1.amazonaws.com/prod/FetchCredentials'
        try {
            const access_token = await getNewToken()
            const response = await fetch(FetchCredentialsUrl, {
                method: 'GET',
                mode: 'cors',
                headers: {
                    'Authorization': access_token.access_token
                },
            },)
            const data = await response.json()
            return data.response.Credentials
        } catch(e) {
            console.log(e)
            throw e
        }
    }

    const {StorageBrowser} = createStorageBrowser({
        config: createManagedAuthAdapter({
            credentialsProvider: async () => {
                const credentials = await fetchCredentials()
                console.log(credentials)
                return  {
                    credentials: {
                        accessKeyId: credentials.AccessKeyId,
                        secretAccessKey: credentials.SecretKey,
                        sessionToken: credentials.SessionToken,
                        expiration: credentials.Expiration,
                    },
                }
            },
            // AWS `region` and `accountId` of the S3 Access Grants Instance.
            region: 'us-east-1',
            accountId: '099115825276',
            // call `onAuthStateChange` when end user auth state changes
            // to clear sensitive data from the `StorageBrowser` state
            registerAuthListener: (onAuthStateChange) => {
            },

        })
    })

    const signOutRedirect = () => {
        window.location.href = `${idpUrl}/logout?client_id=${clientId}&logout_uri=${encodeURIComponent(logoutUri)}`
    }

    const handleLogout = () => {
        auth.removeUser().then(() => {}) // Clear local storage
        signOutRedirect() // Redirect to the identity provider's logout endpoint
    };

    if (auth.isLoading) {
        return <div>Loading...</div>
    }

    if (auth.error) {
        return <div>Encountering error... {auth.error.message}</div>
    }

    if (auth.isAuthenticated) {
        return (
            <>
                <Flex direction="column"
                      justifyContent="flex-start"
                      alignItems="stretch"
                      alignContent="flex-start"
                      wrap="nowrap"
                      gap="1rem">
                    <View as="div" width="100%">
                        <Heading level={1}>Hello {auth.user.profile.name}</Heading>
                        <Button onClick={handleLogout}>Sign out</Button>
                    </View>
                    <View as="div" width="100%">
                        <StorageBrowser/>
                    </View>
                </Flex>
            </>
        )
    }
    return (
        <div>
            <button onClick={() => auth.signinRedirect()}>Sign in</button>
            <button onClick={() => signOutRedirect()}>Sign out</button>
        </div>
    );
}

export default App
