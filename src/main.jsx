import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { AuthProvider } from "react-oidc-context"
import './index.css'
import '@aws-amplify/ui-react/styles.css'
import App from './App.jsx'

const config = {
    authority: "https://login.microsoftonline.com/e0916847-79ae-4d02-9184-ba50443a043d/v2.0/",
    client_id: "2b7c4fc8-2f89-45e1-b537-06de31fd03c5",
    redirect_uri: "http://localhost:5173/",
    response_type: "code",
    scope: "email openid profile api://2b7c4fc8-2f89-45e1-b537-06de31fd03c5/S3AG",
    onSigninCallback: (user) => {
        if (user){
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }
}

const root = createRoot(document.getElementById("root"));
root.render(
    <StrictMode>
        <AuthProvider {...config}>
            <App />
        </AuthProvider>
    </StrictMode>,
)
