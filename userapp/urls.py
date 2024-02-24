from django.urls import path
from . import views


urlpatterns = [
    path('register/', views.UserRegister),
    path('sign-up/', views.QuickRegister),
    path('', views.HomePage),
    path('services/', views.OurServices),
    path('servicefilter/<int:id>/', views.FilterByCategory, name="puja"),
    path('pujadetail/<int:id>/', views.ViewPujaDetail, name='pujadetail'),    
    path('pujaslot/<int:id>/', views.AddPoojaSlot, name="pujaslot"),
    path('viewpujadiscrip/<int:id>/', views.ViewPujadescription, name="viewpuja"),
    path('products/', views.OurProducts),
    path('productfilter/<int:id>/', views.FilterProductByCategory, name="prod"),
    path('horoscope/<int:id>/', views.FilterHoroscopeByCategory, name='horoscope'),
    path('proddetail/<int:id>/', views.ViewProductDetail, name='proddetail'),
    path('addtocart/<int:id>/', views.AddToCart, name="addcart"),
    path('showcart/', views.ViewCartProduct, name="payid"),
    path('viewproddiscrip/<int:id>/', views.ViewProductdescription, name="viewprod"),
    path('checkout/', views.Checkout),
    path('buy/', views.BuyNow),
    path('askquestion/', views.QusAndAnswerView),
    path('askquestionpay/', views.QusAndAnswerViewPayment),
    path('profile/', views.ShowProfileDetail),
    path('editprofile/<int:id>/', views.EditProfileView, name='editpro'),
    path('pujaslot/', views.ViewPujaSlotBooking, name='pujaslot_booking'),
    path('allblogs/', views.DailyBlosView),
    path('friendfunction/', views.FamilyFriendCreate),
    path('getfriendfunction/', views.AddFriendView),
    path('editfriendfunctionpro/<int:id>/', views.EditFriendProfileView, name='editfamilypro'),    
    path('delfriendfunctionpro/<int:id>/', views.DeleteFriendProfile, name='delfamilypro'),
    path('orderlist/', views.GetOrderView),
    path('customersupport/', views.SendCustomerSupport),
    # path('horoscope/', views.HoroscopeView),
    path('faqreply/', views.ShowFAQReply),
    path('prodorder/', views.ShowOrderlist),
    path('pujaorder/', views.ShowPojaSlot),
    path('faqpay/', views.ShowFaqPayment),
    path('deletecart/<int:id>/', views.DeleteCart, name='delcart'),
    path('deletepuja/<int:id>/', views.DeletePoja, name='delpuja'),
    path('addresstoorder/', views.OrderPlaceAddres),
    path('addwallet/', views.AddWalletAmount, name="wallet"),
    path('paymentadmin/',views.PaymentByRazorpay),
    path('paywithwallet/',views.PayWithWallet),
    path('paywithwalletforpuja/',views.PayWithWalletforPuja),
    path('paywithwalletforqa/',views.PayWithWalletforQA),
    path('checkoutforqa/',views.CheckoutforQA),
    path('checkoutforpuja/',views.CheckoutforPuja),
    path('mailpass/',views.SendMailToPassword,name='mailpass'),
    path('changeuserpassword/<int:id>/<str:username>/',views.UserForgotPassword, name='changepass1'),
    
    #path('termsofuse/',views.Termsofuse),
    path('termsandcondition/',views.TermsandCondition),
    path('privacypolicy/',views.PrivacyPolicy),
    path('contact/',views.ContactUs),
    path('shippingpolicy/',views.ShippingPolicy),    
    path('refundpolicy/',views.RefundPolicy),

    path('payment-status/', views.payment_return, name="payment_status"),
    path('wallet/add/success/', views.AddToWalletSuccessView, name="wallet_add_success"),
    path('order/success/', views.OrderSuccessView, name="order_success"),
    path('buy/order/success/', views.BuyOrderSuccessView, name="buy_order_success"),
    path('puja/success/', views.PujaSuccessView, name="puja_success"),
    path('askastro/success/', views.AskAstroSuccessView, name="askastro_success")

]