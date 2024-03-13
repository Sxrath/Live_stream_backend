from django.urls import path
from . import views
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
urlpatterns=[
    path('register/',views.RegistrationView.as_view(), name='register'),
    path('login/',views.LoginView.as_view(),name='login'),
    path('all-users/', views.AllUsers.as_view(), name='all_users'),

    path('CreateFollower/<int:user_id>/', views.CreateFollower.as_view(),name='CreateFollower'),
    path('CreateLike/<int:stream_id>/',views.CreateLike.as_view(),name='CreateLike'),
    path('ListFollowedStreams/',views.ListFollowedStreams.as_view(),name='ListFollowedStreams'),
    path('list-subscribed/', views.ListSubscriptionstream.as_view(),name='listfollowedstreams'),
    path('update-profile/<int:pk>/', views.UpdateProfile.as_view(), name='update-profile'),
    path('StreamCreateView/',views.StreamCreateView.as_view(),name='StreamCreateView'),
    path('report/<int:stream_id>/', views.ReportCreateView.as_view(), name='report-create'),
    path('messages/<int:receiver>/', views.MessageListCreateAPIView.as_view(), name='message-list-create'),
     path('messagesUnreadList/<int:receiver>/', views.MessageListAPIView.as_view(), name='message-list'),
    # path('api/messages/<int:receiver>/', views.MessageListCreateAPIView.as_view(), name='message-list-create'),
    path('api/users/', views.UserListCreateAPIView.as_view(), name='user-list-create'),
    path('api/users/<int:pk>/', views.UserDetailAPIView.as_view(), name='user-detail'),
    path('api/chats/',views.ChatView.as_view(), name='chats'),
    path('messagesallList/<int:receiver>/', views.MessageView.as_view(), name='message-list'),
    # path('api/payment/', views.PaymentView.as_view(), name='payment'),
    path('search/',views.SearchAPIView.as_view(),name='serach'),
    path('subcribe/<int:id>/', views.PayPalPaymentView.as_view(), name='paypal-payment'),

    #firebase-realtime-chat
    # path('streams/<int:stream_id>/create-message/', views.StreamMessageCreateView.as_view(), name='create_message'),
    # path('streams/<int:stream_id>/messages/', views.StreamMessagesView.as_view(), name='retrieve_messages'),
    #like
    path('stream/<int:stream_id>/like_count/', views.get_like_count, name='get_like_count'),
    path('stream/<int:stream_id>/liked_usernames/', views.get_liked_usernames, name='get_liked_usernames'),
    path('Filterby/category/<int:cat_id>/', views.filterbyCategory.as_view(), name='filter_by_category'),
   #livechat
   path('createlive/chat/<int:stream_id>/',views.LivechatCreate.as_view(),name='live-chat-create-api'),
   path('list/live/chat/<int:stream_id>/',views.LivechatList.as_view(),name='live-chat-listing')
   
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)




