
from . import models
from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = models.CustomUser
        fields = ['username', 'email', 'password','first_name','last_name','bio']

    def create(self, validated_data):
        user = models.CustomUser.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if not user:
                msg = 'Unable to log in with provided credentials.'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs
    
class FollowerSerializer(serializers.ModelSerializer):
    class Meta:
        model=models.CustomUser
        fields=[]


class LikeSerializer(serializers.ModelSerializer):
    class Meta:
        model=models.Stream
        fields=[]

class Streamlistserializer(serializers.ModelSerializer):
      category_name=serializers.CharField(source=models.Category.category, read_only=True)
    # username=serializers.CharField(source=models.CustomUser.username, read_only=True)
      class Meta:
        model=models.Stream
        fields=['username','id','title','description','category_name','is_exclusive']


class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model=models.CustomUser
        fields=['first_name','last_name','bio','profile_picture']


class StreamSerializer(serializers.ModelSerializer):

    class Meta:
        model=models.Stream
        fields=['title','description','category','is_exclusive','url','tumbnile']

class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Report
        fields = ['reason']
    
class StreamListSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source='user.username')
    category = serializers.CharField(source='category.category')

    class Meta:
        model = models.Stream
        fields = ['user', 'id', 'tumbnile', 'title', 'description', 'category']

    
# class MessageSerializer(serializers.ModelSerializer):
#     sender = serializers.SlugRelatedField(many=False, slug_field='username', queryset=models.CustomUser.objects.all())
#     receiver = serializers.SlugRelatedField(many=False, slug_field='username', queryset=models.CustomUser.objects.all())

#     class Meta:
#         model = models.Message
#         fields = ['sender', 'receiver', 'message', 'timestamp']

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Message
        fields = ['message']

class MessageListSerializer(serializers.ModelSerializer):
    sender_username = serializers.ReadOnlyField(source='sender.username')
    receiver_username = serializers.ReadOnlyField(source='receiver.username')
    class Meta:
        model = models.Message
        fields = ['sender_username','receiver_username','is_read','timestamp','message']


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=models.CustomUser
        fields=['username','id','first_name','last_name']

# class PaymentSerializer(serializers.Serializer):
#     amount = serializers.DecimalField(max_digits=10, decimal_places=2)
#     token = serializers.CharField(max_length=100)

# class AlluserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model=models.CustomUser
#         fields=['username','id','email',]
class SearchStream(serializers.ModelSerializer):
    category_name=serializers.CharField(source='category.category')
    username=serializers.CharField(source='user.username')

    class Meta:
        model=models.Stream
        fields=['title','category_name','username']

class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model=models.Chat
        fields=['message','user','timestamp']

class ChatlistSerializer(serializers.ModelSerializer):
    username=serializers.CharField(source='user.username')
    class Meta:
        model=models.Chat
        fields=['message','user','timestamp','username']