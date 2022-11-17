from django.urls import path,include
#from rest_framework.urlpatterns import format_suffix_patterns
from myapp.views import * 
from myapp import views

user_list = User_viewset.as_view({
    'get': 'list',
    'post': 'create'
    
})

user_detail = User_viewset.as_view({
    'get': 'retrieve',
    'put': 'update',
    'patch':'partial_update',
    'delete': 'destroy'
})

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'userlist',User_viewset, basename="user")



urlpatterns = [
           
            path('api/', TodoListApiView.as_view(),name = 'api'),
            path('api/<int:todo_id>/', TodoDetailApiView.as_view(),name = 'apidetail'),
            path('', include(router.urls)),
            path('a/', SnippetApiView.as_view(),name = 'a'),
            path('a/<int:id>/', SnippetDetailApiView.as_view(),name = 'i'),
            path('snippet/', views.snippet_list,name = 'snippet'),
            path('snippet/<int:pk>/', views.snippet_detail,name ='snippet_detail'),
            path('s/', SnippetList.as_view(),name = 's'),
            path('sd/<int:pk>', SnippetDetail.as_view(),name = 'sge'),
            path('sge/', SnippetListgen.as_view(),name = 's'),
            path('sdge/<int:pk>', SnippetDetailgen.as_view(),name = 'sdge'),
            path('token/', ExampleView.as_view(),name = 'token'),
            path('register/', RegisterAPI.as_view(), name='register'),
            path('login/', LoginAPI.as_view(), name='login'),
            
            path("details/",UserDetailAPI.as_view()),
            path('register/',RegisterUserAPIView.as_view()),
            path("list/",UserList.as_view()),
            path("detail/<pk>",UserDetail.as_view()),
            path("userlist/",user_list),
            path("userlist/<int:pk>/",user_detail),

    
            
            
        
]     
#urlpatterns = format_suffix_patterns(urlpatterns)
