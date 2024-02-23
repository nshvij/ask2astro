from django.urls import path
from . import views

urlpatterns = [    
    path('index/', views.Homepage),
    # path('', views.Login),
    path('logout/', views.logout_call, name='logout'),
    path('getusers/',views.GetAllUsers),
    path('edituser/<int:id>/', views.UpdateUser, name="update_user"),
    path('delete_user/<int:id>/', views.DeleteUser, name='del_user'),
    path('viewprofile/<int:id>/', views.ViewProfiled, name='prof'),
    
    path('changepassword/<int:id>/',views.ForgotPassword, name='changepass'),
    
    path('addpandit/',views.CreatePanditJi),
    path('getpandit/',views.GetAllPandit),
    path('editpandit/<int:id>/', views.UpdatePandit, name="update_cor"),
    path('delete_pandit/<int:id>/', views.DeletePandit, name='del_cor'),
    
    path('addcategory/',views.CategoryOfProductView),
    path('getcategory/',views.GetAllCategoryOfProduct),
    path('editcategory/<int:id>/', views.UpdateCategoryOfProduct, name="speciality"),
    path('delete_category/<int:id>/', views.DeleteCategoryOfProduct, name='del_spe'),
    
    path('addhoroscopcate/',views.CreateHoroscopeCategory),
    path('gethoroscopcate/',views.GetAllHoroscopeCategory),
    path('edithoroscopcate/<int:id>/', views.UpdateHoroscopeCategory, name="update_gp"),
    path('delete_horoscopcate/<int:id>/', views.DeleteHoroscopeCategory, name='del_gp'),
    
    path('addproducts/',views.CreateProducts),
    path('getproducts/',views.GetAllProducts),
    path('editproducts/<int:id>/', views.UpdateProducts, name="update_pati"),
    path('delete_products/<int:id>/', views.DeleteProducts, name='del_pati'),
    path('viewproddetail/<int:id>/', views.ProductDetail, name='view_proddetail'),
    
    
    
    path('addpuja/',views.CreatePooja),
    path('getpuja/',views.GetAllPuja),
    path('editpuja/<int:id>/', views.UpdatePujaDetail, name="update_poja"),
    path('delete_puja/<int:id>/', views.DeletePujaDetail, name='del_puja'),
    path('viewpujadetail/<int:id>/', views.PujaDetail, name='view_pujadetail'),
  
    
    path('getpoojaslot/',views.GetAllPujaSlot),
    path('editpojabooking/<int:id>/', views.UpdatPujabookDetail, name="update_puja"),
    path('vieprofile2/<int:id>/', views.GetViewPujaSlotprofile, name="view_profile2"),
    
    path('getproductorder/',views.GetAllProductOrder),
    path('editorder/<int:id>/', views.UpdateOrderDetail, name="update_ord"),    
    path('vieprofile/<int:id>/', views.GetViewprofile, name="view_profile"),
    
    
    path('addslottime/',views.CreateSlotTime),
    path('getslottime/',views.GetAllTimeSlot),
    path('editslottime/<int:id>/', views.UpdateSlotTime, name="update_slt"),
    path('delete_slottime/<int:id>/', views.DeleteSlotTime, name='del_slt'),
    
    path('addpujacategory/',views.CreateCategoryOfPooja),
    path('getpujacategory/',views.GetAllCategoryOfPooja),
    path('editpujacategory/<int:id>/', views.UpdateCategoryOfPooja, name="update_rol"),
    path('delete_pujacategory/<int:id>/', views.DeleteCategoryOfPooja, name='del_rol'),

    
    path('addfaqcategory/',views.CategoryOfFAQView),
    path('getfaqcategory/',views.GetAllCategoryOfFAQ),
    path('editfaqcategory/<int:id>/', views.UpdateCategoryOfFAQ, name="update_ask"),
    path('delete_faqcategory/<int:id>/', views.DeleteFAQDetail, name='del_faq'),
    
    path('addfaqasktime/',views.AskTimeOfFAQView),
    path('getfaqasktime/',views.GetAllAskTimeOfFAQ),
    path('editfaqasktime/<int:id>/', views.UpdateAskTimeOfFAQ, name="update_tim"),
    path('delete_faqasktime/<int:id>/', views.DeleteAskTimeFAQDetail, name='del_tim'),
    
    path('getfaq/',views.GetAllQusAndAnswerOfFAQ),    
    path('editfaq/<int:id>/', views.UpdateQusAndAnswerDetail, name="update_faq"),
    path('viepmyrofile/<int:id>/', views.GetViewQusAndAnswerprofile, name="view_profile3"),
    path('viewquest/<int:id>/', views.GetViewQusAndAnswerAskQus, name="view_qus1"),
    
    
    path('addblog/',views.CreateBlog),
    path('getblog/',views.GetAllBlog),
    path('editblog/<int:id>/', views.UpdateBlog, name="update_blog"),
    path('delete_blog/<int:id>/', views.DeleteBlog, name='del_blog'),
    path('viewblog/<int:id>/', views.GetViewDailyBlogs, name="view_blog"),
    
    
    path('getsupport/',views.GetAllCustomerSupport),
    path('viepmyrofile4/<int:id>/', views.GetViewcustomersupportprofile, name="view_profile4"),
    # path('editsupport/<int:id>/', views.UpdateCustomerSupport, name="update_supp"),
    
    # path('addfaqasktime/',views.AskTimeOfFAQView),
    path('getfamilyfriend/',views.FamilyandFriendView),
    # path('editfaqasktime/<int:id>/', views.UpdateAskTimeOfFAQ, name="update_tim"),
    # path('delete_faqasktime/<int:id>/', views.DeleteAskTimeFAQDetail, name='del_tim'),
    path('viewfamilyfriend/<int:id>/', views.FamilyFriendDetailPage, name="famfri_view"),
    path('viewaskprofile/<int:id>/', views.GetViewAskByprofile, name="prof_view"),
    
    path('getaskquetionhis/',views.GetAllPayHistoryAsk),
    path('viepmyrofile5/<int:id>/', views.GetViewPaymentprofile, name="view_profile5"),
    path('editaskpayhis/<int:id>/', views.UpdateAskPayDetail, name="update_askpay"),
    
    path('addcountrycode/',views.CreateCountryCode),
    path('getcountrycode/',views.GetAllCountryCode),
    path('editcountrycode/<int:id>/', views.EditCountryCode, name="update_code"),
    path('delete_code/<int:id>/', views.DeleteCountryCode, name='del_code'),
    
    path('allpendingorder/', views.GetPendingOrder),
    path('allpendingpuja/', views.GetPendingPujaBook),
    
    
    path('allcarts/', views.GetAllCarts),
    path('allpujacarts/', views.GetAllPujaCarts),
  
]