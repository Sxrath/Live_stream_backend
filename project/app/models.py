from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.conf import settings

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, blank=True, null=True,unique=True)
    bio=models.TextField(blank=True)
    first_name = models.CharField(max_length=300)
    last_name=models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    is_admin=models.BooleanField(default=False)
    is_user=models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    following = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='following_profiles',blank=True)
    follower = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='follower_profiles',blank=True)
    subscribing=models.ManyToManyField(settings.AUTH_USER_MODEL,related_name='subscribing_profile',blank=True)
    subscriber=models.ManyToManyField(settings.AUTH_USER_MODEL,related_name='subscriber_profile',blank=True)
    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
     if self.username:
        return self.username
     else:
        return self.email
    def follower_count(self):
        return self.follower.count()
    def follower_usernames(self):
        return [user.username  for user in self.follower.all()]
    def following_count(self):
        return self.following.count()
    def following_names(self):
        return [user.username for user in self.following.all()]
    def subscriber_count(self):
        return self.subscriber.count()
    def subscriber_names(self):
        return [user.username for user in self.subscriber.all()]
    def subscribing_count(self):
         return self.subscriber.count()
    def subscribing_names(self):
        return [user.username for user in self.subscribing.all()]

class Category(models.Model):
    category=models.CharField(max_length=500)

    def __str__(self) -> str:
        return self.category
    
class Stream(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()
    category= models.ForeignKey(Category,on_delete=models.CASCADE)
    is_exclusive = models.BooleanField(default=False)
    liked_by = models.ManyToManyField(CustomUser,related_name='created_streams',blank=True)
    tumbnile=models.ImageField(upload_to="tumbniles",default=None)
    url=models.TextField(default=None,blank=True,null=True)

    def like_count(self):
        return self.liked_by.count()
    def liked_usernames(self):
        return [user.username for user in self.liked_by.all()]
     
class Report(models.Model):
    video = models.ForeignKey(Stream, on_delete=models.CASCADE)
    reporter = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    reason = models.TextField()
    def __str__(self) -> str:
        return f'{self.reporter} report on {self.video}'


from django.contrib.auth import get_user_model
class Chat(models.Model):
    stream = models.ForeignKey(Stream, on_delete=models.CASCADE)
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)  
    message = models.TextField()
    timestamp = models.TimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.username} on {self.stream.title}: {self.message}'
    

class Message(models.Model):
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sender')
    receiver = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='receiver')
    message = models.CharField(max_length=1200)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return self.message

    class Meta:
        ordering = ('timestamp',)
