from django.shortcuts import render
from django.http import HttpResponse
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
# Create your views here.
from .serializers import SignUpSerializer
from google_auth_oauthlib.flow import Flow
from django.conf import settings
from django.shortcuts import redirect
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from datetime import datetime
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.utils import make_msgid
from googleapiclient.discovery import build
from .models import GmailCredentials
from django.contrib.auth.models import User
from rest_framework_simplejwt.authentication import JWTAuthentication
import urllib.parse
import json, base64
class SignUpVIew(APIView):
    permission_classes= (AllowAny,)

    def post(self,request):
        # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>..",request.data)
        serializer= SignUpSerializer(data=request.data)

        if serializer.is_valid():
            user= serializer.save()

            refresh= RefreshToken.for_user(user)

            return Response(
                {
                    "id" : user.id,
                    "email": user.email,
                    "access": str(refresh.access_token),
                    "refresh" : str(refresh)
                },
                status= status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GoogleLogin(APIView):
    permission_classes = [IsAuthenticated]    

    def get(self, request):
        user= request.user
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
                    "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=["https://www.googleapis.com/auth/gmail.send"],
            redirect_uri=settings.GOOGLE_OAUTH_REDIRECT_URI,
        )
        print(">>>>>>>>>>>>>>>>>>flow",flow.__dict__)
        state_data={"user_id": user.id}
        encoded_state= base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()
        # store state in session
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state= encoded_state
        )
        print("req.user>>>>>>>>>>>>>>>>>>", request.user)
        # request.session["google_oauth_state"] = state
        # request.session["user_id"] = user.id

        return Response({"auth_url" : auth_url }) 

@api_view(['GET'])
@permission_classes([AllowAny])   # Google callback is public
def google_callback(request):
    state_param= request.GET.get("state")
    state= json.loads(base64.urlsafe_b64decode(state_param).decode())
    user_id= state.get("user_id")
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
                "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=["https://www.googleapis.com/auth/gmail.send"],
        redirect_uri=settings.GOOGLE_OAUTH_REDIRECT_URI
    )

    flow.fetch_token(authorization_response=request.build_absolute_uri())
    creds = flow.credentials
    
    if not user_id:
        return Response({"error": "No user stored in session"}, status=400)

    user = User.objects.get(id=user_id)

    GmailCredentials.objects.update_or_create(
        user=user,
        defaults={
            "access_token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": " ".join(creds.scopes),
            "expiry": creds.expiry,
        }
    )
    redirect_url= f"{settings.FRONTEND_URL}/cold-email-form"
    return redirect(redirect_url)

class sendEmail(APIView):
    permission_classes= (IsAuthenticated,)
    def post(self,request):
        user = request.user
        creds_obj = GmailCredentials.objects.get(user=user)

        creds = Credentials(
            token=creds_obj.access_token,
            refresh_token=creds_obj.refresh_token,
            token_uri=creds_obj.token_uri,
            client_id=creds_obj.client_id,
            client_secret=creds_obj.client_secret,
            scopes=creds_obj.scopes.split(" "),
        )

        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            creds_obj.access_token = creds.token
            creds_obj.expiry = creds.expiry
            creds_obj.save()

        service = build("gmail", "v1", credentials=creds)

        # Build email message
        raw_to = request.POST.get("to", "")
        if not raw_to:
            return Response({"error" : "no recipient added"}, status=400)
        recipients = [e.strip() for e in raw_to.split(",") if e.strip()]
        results=[]
        body=request.POST.get("body")
        subject= request.POST.get("subject")
        file= request.FILES.get("file")
            

        
        for email in recipients:

            message = MIMEMultipart()
            message["to"] = email
            message["subject"] = subject
            message["Message-ID"]= make_msgid()
            message.attach(MIMEText(body, "html"))
            if file:
                mime_part= MIMEBase('application', 'octet-stream')
                mime_part.set_payload(file.read())
                encoders.encode_base64(mime_part)
                mime_part.add_header(
                    'content-disposition',
                    f'attachment; filename= "{file.name}"'
                )
                message.attach(mime_part)

            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            message_body = {"raw": raw}

            result = service.users().messages().send(
                userId="me", body=message_body
            ).execute()

            results.append({"to": email, "id": result["id"]})
        return Response({"status": "sent", "results": results})
        

class getGmailConnectionStatus(APIView):
    def get(self,request):
        try:
            connection_status= GmailCredentials.objects.filter(user=request.user).exists()
            return Response({"gmail_connected" : connection_status},status=200)
        except Exception as e:
            return Response({"Error" : e},status=500)