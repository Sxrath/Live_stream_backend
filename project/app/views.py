
from django.conf import settings
from django.shortcuts import render, redirect
from django.views import View
from .  models import CustomUser
from . import models
from rest_framework import generics
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegistrationSerializer
from django.contrib.auth import authenticate
from rest_framework import generics, status
from . import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import generics, permissions, status
from django.shortcuts import get_object_or_404
from django.http import JsonResponse

class RegistrationView(generics.CreateAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': user.username,
            'email': user.email,
            'first_name':user.first_name,
            'last_name':user.last_name,
            'id':user.id,
            'follower_count':user.follower_count(),
            'follower_users':user.follower_usernames(),
            'following_count':user.following_count(),
            'following_users':user.following_names()

      })


class LoginView(generics.GenericAPIView):
    serializer_class = serializers.LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')

        user = authenticate(request, username=username, password=password)

        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'id':user.id,
                'follower_count':user.follower_count(),
                'follower_users':user.follower_usernames(),
                'following_count':user.following_count(),
                'following_users':user.following_names(),
                'subscriber_count':user.subscriber_count(),
                'subscriber_names':user.subscriber_names(),
                'subscribing_count':user.subscribing_count(),
                'subscribing_names':user.subscribing_names(),
                'bio':user.bio,

               'profile_pic':user.profile_picture.url if user.profile_picture else None

    
            })
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class CreateFollower(generics.CreateAPIView):
    serializer_class = serializers.FollowerSerializer

    def create(self, request, *args, **kwargs):
        user_id = self.kwargs.get("user_id")
        profile_instance = get_object_or_404(CustomUser, id=user_id)

        if profile_instance.follower.filter(id=request.user.id).exists():
            profile_instance.follower.remove(request.user)
            request.user.following.remove(profile_instance)
            return Response({'detail': 'Following removed successfully'}, status=status.HTTP_200_OK)
        else:
            profile_instance.follower.add(request.user)
            request.user.following.add(profile_instance)
            return Response({'detail': 'Following added successfully'}, status=status.HTTP_201_CREATED)

from django.contrib.auth.models import AnonymousUser
class CreateLike(generics.CreateAPIView):
    queryset = models.Stream.objects.all()
    serializer_class = serializers.LikeSerializer

    def create(self, request, *args, **kwargs):
        # Check if user is authenticated
        if not request.user.is_authenticated:
            return Response({'detail': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        
        stream_id = self.kwargs.get("stream_id")
        stream = get_object_or_404(models.Stream, id=stream_id)

        user = self.request.user
        if isinstance(user, AnonymousUser):
            return Response({'detail': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        if stream.liked_by.filter(id=user.id).exists():
            stream.liked_by.remove(user)
            return Response({'detail': 'Like removed successfully'}, status=status.HTTP_200_OK)
        else:
            stream.liked_by.add(user)
            return Response({'detail': 'Like added successfully'}, status=status.HTTP_201_CREATED)


class ListFollowedStreams(generics.ListAPIView):
    serializer_class = serializers.Streamlistserializer

    def get_queryset(self):
        user = self.request.user
        queryset = models.Stream.objects.filter(user__follower=user, is_exclusive=False)
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        if not queryset.exists():
            return Response({'detail': 'No streams found for the users you are following.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class ListSubscriptionstream(generics.ListAPIView):
    serializer_class = serializers.Streamlistserializer

    def get_queryset(self):
        user = self.request.user
        profile_instance = get_object_or_404(CustomUser, user=user)
        subscribed_users = profile_instance.subscribing.all()
        queryset = models.Stream.objects.filter(user__in=subscribed_users, is_exclusive=True)
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        if not queryset.exists():
            return Response({'detail': 'No streams found for the users you are subscribing.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UpdateProfile(generics.RetrieveUpdateAPIView):
    serializer_class = serializers.UpdateUserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user_id = self.kwargs.get('pk')
        queryset = CustomUser.objects.filter(id=user_id)
        return queryset

    def perform_update(self, serializer):
        serializer.save()

# class StreamCreateView(generics.ListCreateAPIView):
#     queryset = models.Stream.objects.all()
#     serializer_class = serializers.StreamSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)


class ReportCreateView(generics.CreateAPIView):
    serializer_class = serializers.ReportSerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        stream_id = self.kwargs.get('stream_id')
        stream = get_object_or_404(models.Stream, pk=stream_id)

        reporter_id = self.request.user.id

        # Check if the user has already reported this stream
        if models.Report.objects.filter(video=stream, reporter_id=reporter_id).exists():
            return Response({'detail': 'You have already reported this stream.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data={'video': stream_id, 'reporter': reporter_id, 'reason': request.data.get('reason', '')})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        report_count = models.Report.objects.filter(video=stream).count()

        if report_count >= 10:
            stream.delete()
            return Response({'detail': 'Stream has been deleted due to multiple reports.'}, status=status.HTTP_204_NO_CONTENT)

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    


##################### message #################################
    

# class MessageListCreateAPIView(generics.ListCreateAPIView):
#     serializer_class = serializers.MessageSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     def get_queryset(self):
#         receiver_id = self.kwargs['receiver']
#         # Mark messages as read
#         messages =models.Message.objects.filter(receiver_id=receiver_id, is_read=False)
#         for message in messages:
#             message.is_read = True
#             message.save()
#         return messages

#     def perform_create(self, serializer):
#         receiver_id = self.kwargs.get('receiver_id')
#         receiver = get_object_or_404(CustomUser, id=receiver_id)
#         serializer.save(sender=self.request.user, receiver=receiver)

#     def create(self, request, *args, **kwargs):
#         # Automatically set the receiver ID from the URL
#         request.data['receiver'] = kwargs['receiver']
#         # Set the sender as the logged-in user
#         request.data['sender'] = self.request.user.id
#         return super().create(request, *args, **kwargs)
    
class MessageListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = serializers.MessageSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        receiver_id = self.kwargs['receiver']
        # Mark messages as read
        messages = models.Message.objects.filter(receiver_id=receiver_id, is_read=False)
        for message in messages:
            message.is_read = True
            message.save()
        return messages
    
    def perform_create(self, serializer):
        receiver_id = self.kwargs.get('receiver')
        receiver = get_object_or_404(models.CustomUser, id=receiver_id)
        serializer.save(sender=self.request.user, receiver=receiver)


class MessageListAPIView(generics.ListAPIView):
    serializer_class = serializers.MessageListSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        receiver_id = self.kwargs['receiver']
        # Mark messages as read
        messages = models.Message.objects.filter(receiver_id=receiver_id,  is_read=False)
        for message in messages:
            message.is_read = True
            message.save()
        return messages
        

class UserListCreateAPIView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = serializers.UserSerializer
    permission_classes = [permissions.IsAuthenticated]

class UserDetailAPIView(generics.RetrieveAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = serializers.UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class ChatView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'error': 'User not authenticated'})
        users = CustomUser.objects.exclude(username=request.user.username)
        serializer = serializers.UserSerializer(users, many=True)
        return Response(serializer.data)

class MessageView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.MessageListSerializer

    def get_queryset(self):
        sender = self.request.user.id
        receiver = self.kwargs.get('receiver')
        queryset = models.Message.objects.filter(sender_id=sender, receiver_id=receiver) | \
                   models.Message.objects.filter(sender_id=receiver, receiver_id=sender)
        return queryset
    
# from django.conf import settings
# from .serializers import PaymentSerializer
# import stripe
# stripe.api_key = settings.STRIPE_SECRET_KEY

# class PaymentView(APIView):
#     def post(self, request):
#         serializer = PaymentSerializer(data=request.data)
#         if serializer.is_valid():
#             # Retrieve validated data
#             amount = serializer.validated_data.get('amount')
#             # token = serializer.validated_data.get('token')
#             token = stripe.Token.create(
#                 card={
#                     "number": "4242424242424242",
#                     "exp_month": 12,
#                     "exp_year": 2024,
#                     "cvc": "123"
#                 },
#             )

#             print(token.id)

#             try:
#                 # Create a charge
#                 charge = stripe.Charge.create(
#                     amount=int(amount * 100),  # Convert to cents
#                     currency='usd',
#                     source=token,
#                     description='Example charge'
#                 )
#                 # If successful, return success response
#                 return Response({'message': 'Payment successful'})
#             except stripe.error.StripeError as e:
#                 # If there's an error, return error response
#                 return Response({'error': str(e)})
#         else:
#             # If serializer is not valid, return validation errors
#             return Response(serializer.errors, status=400)


class SearchAPIView(generics.ListAPIView):
    queryset = models.Stream.objects.all()
    serializer_class = serializers.SearchStream

    def get(self, request, *args, **kwargs):
        query = request.query_params.get('q', None)
        if query:
            result = self.queryset.filter(title__icontains=query) | \
                     self.queryset.filter(user__username__icontains=query) | \
                     self.queryset.filter(category__category__icontains=query)
            serializer = self.get_serializer(result, many=True)
            return Response(serializer.data)
        else:
            return Response({"error": "Please provide a search query."}, status=status.HTTP_400_BAD_REQUEST)
        

# payments/views.py
from django.conf import settings

import paypalrestsdk
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from . import models

class PayPalPaymentView(APIView):
    def post(self, request, *args, **kwargs):
        # Initialize PayPal client using settings
        paypalrestsdk.configure({
            "mode": "sandbox",  # Change to "live" for production
            "client_id": settings.PAYPAL_CLIENT_ID,
            "client_secret": settings.PAYPAL_CLIENT_SECRET
        })

        id = self.kwargs.get('id')  # Get the profile ID from URL
        profile_instance = get_object_or_404(models.CustomUser, id=id)
        user = request.user

        amount = request.data.get('amount')
        currency = request.data.get('currency', 'USD')  # Default currency is USD

        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "transactions": [{
                "amount": {
                    "total": str(amount),
                    "currency": currency
                }
            }],
            "redirect_urls": {
                "return_url": "http://localhost:8000/payment/success",
                "cancel_url": "http://localhost:8000/payment/cancel"
            }
        })

        if payment.create():
            # Payment created successfully, return approval URL
            if profile_instance.subscriber.filter(id=request.user.id).exists():
                return Response({'detail': 'You cannot subscribe again'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                profile_instance.subscriber.add(user)
                request.user.subscribing.add(profile_instance.id)
            return Response({"approval_url": payment.links[1].href})
        else:
            # Payment creation failed
            return Response({"error": payment.error}, status=status.HTTP_400_BAD_REQUEST)

# class PayPalPaymentView(APIView):
    
#     def post(self, request):
#         amount = request.data.get('amount')
#         currency = request.data.get('currency', 'USD')  # Default currency is USD

#         payment = paypalrestsdk.Payment({
#           "intent": "sale",
#           "payer": {
#             "payment_method": "paypal"
#           },
#           "transactions": [{
#             "amount": {
#               "total": str(amount),
#               "currency": currency
#             }
#           }],
#           "redirect_urls": {
#             "return_url": "http://localhost:8000/payment/success",
#             "cancel_url": "http://localhost:8000/payment/cancel"
#           }
#         })

#         if payment.create():
#             # Payment created successfully, return approval URL
#             return Response({"approval_url": payment.links[1].href})
#         else:
#             # Payment creation failed
#             return Response({"error": payment.error}, status=status.HTTP_400_BAD_REQUEST)
# #livechat-firebase
# import firebase_admin
# from firebase_admin import credentials
# cred = credentials.Certificate({
#   "type": "service_account",
#   "project_id": "livestream-e4c9b",
#   "private_key_id": "03401e22beb48026af8f3d6d950f99eccbea5ea5",
#   "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDI24QT+uKg5wad\nJIUc70Y6fKE/5a5F4MVTdsFz1ScSdSqBswyjG5q0+s/HpT6xwQB5Q8iURPigUEeW\n6z3ASOAo9Cc+BWylFwEoZxxE2YlS+6cnPR5uTHidGr6H4AtpiAlv2z+oTNo4Y5vQ\nMDrfVWQCkOw5zmawyOPOsFtn5XcDoM5NJybY1QPA63rcfxidHjfeE9dj46in/6+o\nUp5RRX/sAZIayPLRKnbWYx8/eBDLIG081uK8RA171HHK5YmzMH7AgTsmoiTNuicL\nxPVTKa5L7vstl2d5YRPZHWwFE3vIeqHIroI4BIVzAWf9c4L1L4q6dLBrG4nYNfoK\nmN1DmzFXAgMBAAECggEAWZfZPVROnLkQcS3mFncAm3wWLTtVViQhwM4bEoEEsa4D\nrODiBSt+AbZS0ln6Mi3F+VFr+f8d69yDYmVCITAglQP7MSYYRTeSs6Pyrx9dqt9H\nuy//D/IaZvGUBWXBkWw10Wg55+eH+1krGl05FX+wYZilVk+j7L1fKEXwL9LiGIJq\nOfWp4C5NIsjDPnu7jLl4W1F5Kn76NL+Tci8N8+AR59foYseTRBGZobVSBljgGpX7\nvnKOOfmYlk1Pu3lojjFzXCaCNEMOe3fRP8Du3xRvNOGfKsK+iBkywincQWg3257B\n8Kxom4PezhoHFCbl2q0Nn0RxmWaS5DPMwvX7pEKYEQKBgQD1KFIH/j6Wzo/oaFv/\nbkIkCcDLJsAJH2BW13IflJv99X5DVADNKJdG4LM90xUvVjZa0vu6OdBdlJ1JtA7W\n9IbW4hA2AQ/jQgM7q6LxheAzHy/YMA3h5RVIffg7A5a+1hKsPzYL1OuR2Ggfhb0v\nN2g/xB3ri1ws98SKWDZKvzOZDwKBgQDRvaEqU8KBtZeaRY7AK6v/5Bs+FdFlOwAT\n2tjXDeBfpOWvNH4hcM0lMcMUKCsX3H56TjK5f5KEMl7wvJXggTjSokoMHpkosmj7\ni4yy29bADm48rAaUyIARR4GTlWSFoz5/XPsVMPnF5nJSEp52r7cW3xjAZETj8z0j\ncyJDQx4TOQKBgQDrLGakrEw2Nqjt9U5rVcW09HYxa1bEaYjtRXeAu/p4QEuDIs4y\nAEI+B8dqA1dLNZSmw8Ye+t7bJnlL/qJNqfy/ndSXOaWYB/c6Aogo0Jgl8kDfThnD\nHRKxm8XINsUhBBKdkXWzG+lu2v3nX1AAP1KN+QAKuIEP0g6D9+L9CTXiGQKBgEke\nQZQe9R0A8GQAwb4uu1yO6gxf0MrooaNKVPPLy5+sPcIxm5MO3wWLboWVZ0h/Prxm\njHpsheh+Iujr5ZgJlIShvQyykhRE9iJTSO6Fgz0bCsUt93Fg4Hyln/+SQiPwf/Yo\ntQNzOnAKYWpJQWMA6OQZTGity/JntrWoCpbGTDLJAoGAFtc+wXCQWrEhg2RjGAYn\nWIx/YrNSz49cTEr3mg1L06DiWVYMy2aYHfjE2dxkYp8MplmvspjGFuefAB3N0wxb\nmMoai94x3LJB7KjTdfnuGrKs1H1mNTxsprLCJ/MkyVHudd9IuZFV0dcLUd42WKYm\nJwLvc2ZlRbtw3xCNi5nSQVc=\n-----END PRIVATE KEY-----\n",
#   "client_email": "firebase-adminsdk-4kngh@livestream-e4c9b.iam.gserviceaccount.com",
#   "client_id": "117478895049438218953",
#   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#   "token_uri": "https://oauth2.googleapis.com/token",
#   "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
#   "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-4kngh%40livestream-e4c9b.iam.gserviceaccount.com",
#   "universe_domain": "googleapis.com"
# })

# firebase_admin.initialize_app(cred, {
#     'databaseURL': 'https://livestream-e4c9b-default-rtdb.firebaseio.com/'  # Replace with your database URL
# })
# # views.py
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import IsAuthenticated
# from firebase_admin import db
# from .models import Stream

# # views.py
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework.permissions import IsAuthenticated
# from firebase_admin import db
# from .models import Stream

# class StreamMessageCreateView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request, stream_id, format=None):
#         data = request.data
#         message_text = data.get('text', '')

#         try:
#             stream = Stream.objects.get(pk=stream_id)
#         except Stream.DoesNotExist:
#             return Response({"error": "Stream does not exist"}, status=404)

#         # Get the logged-in user
#         user = request.user

#         # Push message data to Firebase under the user's path and the stream's path
#         user_messages_ref = db.reference(f'/users/{user.id}/messages')
#         stream_messages_ref = db.reference(f'/streams/{stream_id}/messages')

#         # Push message data to Firebase in real-time
#         new_message_ref = user_messages_ref.push({
#             'text': message_text,
#             'stream_id': stream_id,
#             'user_id': user.id,
#             'username': user.username
#             # Other message data as needed
#         })

#         # Also push message to stream's messages
#         stream_message_ref = stream_messages_ref.push({
#             'text': message_text,
#             'user_id': user.id,
#             'username': user.username
#             # Other message data as needed
#         })

#         # Return the message ID as response
#         return Response({"message": "Message created successfully", "message_id": new_message_ref.key,"user":user.username}, status=201)
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from firebase_admin import db

# class StreamMessagesView(APIView):
#     def get(self, request, stream_id, format=None):
#         try:
#             # Reference to the stream's messages in Firebase
#             stream_messages_ref = db.reference(f'/streams/{stream_id}/messages')
#             # Get the snapshot of the messages
#             messages_snapshot = stream_messages_ref.get()
            
#             # Check if there are any messages
#             if messages_snapshot is None:
#                 return Response({"message": "No messages found for this stream"}, status=404)
            
#             # Convert the snapshot to a list of messages
#             messages = [{key: value} for key, value in messages_snapshot.items()]
            
#             return Response({"messages": messages}, status=200)
#         except Exception as e:
#             return Response({"error": str(e)}, status=500)

##______________________________________________________________
        

#likecount and list
def get_like_count(request, stream_id):
    try:
        stream = models.Stream.objects.get(pk=stream_id)
        like_count = stream.liked_by.count()
        return JsonResponse({'like_count': like_count})
    except models.Stream.DoesNotExist:
        return JsonResponse({'error': 'Stream does not exist'}, status=404)

def get_liked_usernames(request, stream_id):
    try:
        stream = models.Stream.objects.get(pk=stream_id)
        liked_usernames = stream.liked_usernames()
        return JsonResponse({'liked_usernames': liked_usernames})
    except models.Stream.DoesNotExist:
        return JsonResponse({'error': 'Stream does not exist'}, status=404)
    
##


class filterbyCategory(generics.ListAPIView):
    serializer_class=serializers.StreamListSerializer
    queryset=models.Stream.objects.all()
    def get_queryset(self):
        cat_id=self.kwargs['cat_id']
        query=models.Stream.objects.filter(category=cat_id)
        return query
    


class AllUsers(generics.ListAPIView):
    serializer_class = serializers.UserSerializer
    queryset = CustomUser.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data

        for user_data in data:
            user_id = user_data['id']
            try:
                user = CustomUser.objects.get(id=user_id)
                user_data['subscriber_count'] = user.subscriber_count()
                user_data['subscriber_names'] = user.subscriber_names()
                user_data['subscribing_names'] = user.subscribing_names()
                user_data['subscribing_count'] = user.subscribing_count()
                user_data['follower_count'] = user.follower_count()
                user_data['follower_usernames'] = user.follower_usernames()
                user_data['following_count'] = user.following_count()
                user_data['following_names'] = user.following_names()
                user_data['profile_picture'] = user.profile_picture.url if user.profile_picture else None
                user_data['bio']=user.bio
            except CustomUser.DoesNotExist:
                # Handle the case where user doesn't exist
                pass
            except Exception as e:
                # Handle any other exceptions gracefully
                pass

        return Response(data)
    
    #livechat-normal-database
class LivechatCreate(generics.CreateAPIView):
    serializer_class = serializers.ChatSerializer
    queryset = models.Chat.objects.all()

    def perform_create(self, serializer):
        stream_id = self.kwargs['stream_id']
        serializer.save(stream_id=stream_id)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class LivechatList(generics.ListAPIView):
    serializer_class=serializers.ChatlistSerializer
    queryset=models.Chat.objects.all()
    def get_queryset(self):
        stream_id=self.kwargs['stream_id']
        query=models.Chat.objects.filter(stream=stream_id)
        return query
    

    #pimux-streaming
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from . import models
from . import serializers

class StreamCreateView(generics.ListCreateAPIView):
    queryset = models.Stream.objects.all()
    serializer_class = serializers.StreamSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def post(self, request, *args, **kwargs):
        # Replace "your_youtube_stream_key" with your actual YouTube RTMPS stream key
        stream_key = "d91v-pq6m-kxq6-urvv-a4zj"
        
        if stream_key:
            # Save the stream details in the database
            data = {'stream_key': stream_key, **request.data}  # Merge explicitly defined stream_key with request data
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            
            # Construct the stream URL for YouTube Live
            stream_url = f"rtmps://a.rtmps.youtube.com/live2/{stream_key}"
            
            return Response({"stream_url": stream_url}, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "Stream key not provided"}, status=status.HTTP_400_BAD_REQUEST)
