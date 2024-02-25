from django.urls import path
from . import views


urlpatterns = [
    path('register/', views.UserRegister),
    path('sign-up/', views.QuickRegister),
    path('', views.HomePage),
    path('puja/', views.OurServices),
    path('puja/category/<int:id>/', views.FilterByCategory, name="puja"),
    path('puja-detail/<int:id>/', views.ViewPujaDetail, name='pujadetail'),
    path('puja-slot/', views.ViewPujaSlotBooking, name='pujaslot_booking'),
    path('puja-slot/<int:id>/', views.AddPoojaSlot, name="pujaslot"),
    path('view-puja-description/<int:id>/', views.ViewPujadescription, name="viewpuja"),
    path('products/', views.OurProducts),
    path('products/category/<int:id>/', views.FilterProductByCategory, name="prod"),
    path('horoscope/<int:id>/', views.FilterHoroscopeByCategory, name='horoscope'),
    path('product-detail/<int:id>/', views.ViewProductDetail, name='proddetail'),
    path('add-to-cart/<int:id>/', views.AddToCart, name="addcart"),
    path('view-cart/', views.ViewCartProduct, name="payid"),
    path('update-cart/', views.UpdateCartProduct, name="update_cart"),
    path('view-product-description/<int:id>/', views.ViewProductdescription, name="viewprod"),
    path('cart/checkout/', views.Checkout),
    path('product/checkout/', views.BuyNow, name='buy_now'),
    path('service/ask-a-question/', views.QusAndAnswerView),
    path('service/ask-a-question/checkout/', views.QusAndAnswerViewPayment),
    path('profile/', views.ShowProfileDetail),
    path('edit-profile/<int:id>/', views.EditProfileView, name='editpro'),
    path('blogs/', views.DailyBlosView),
    path('family-friend-create/', views.FamilyFriendCreate),
    path('view-family-friend/', views.AddFriendView),
    path('edit-friend-profile/<int:id>/', views.EditFriendProfileView, name='editfamilypro'),    
    path('delete-friend-profile/<int:id>/', views.DeleteFriendProfile, name='delfamilypro'),
    path('order-history/', views.GetOrderView),
    path('customer-support/', views.SendCustomerSupport),
    # path('horoscope/', views.HoroscopeView),
    path('service/questions/reply/', views.ShowFAQReply),
    path('product/order/history/', views.ShowOrderlist),
    path('puja/order/history/', views.ShowPojaSlot),
    path('service/ask-a-question/payment/history/', views.ShowFaqPayment),
    path('delete-item/<int:id>/', views.DeleteCart, name='delcart'),
    path('delete-puja-slot/<int:id>/', views.DeletePoja, name='delpuja'),
    path('delivery-address/', views.OrderPlaceAddres),
    path('add-to-wallet/', views.AddWalletAmount, name="wallet"),
    path('confirm-payment/',views.PaymentByRazorpay),
    path('pay-with-wallet/',views.PayWithWallet),
    path('puja/pay-with-wallet/',views.PayWithWalletforPuja),
    path('service/questions/pay-with-wallet/',views.PayWithWalletforQA),
    path('service/questions/checkout/',views.CheckoutforQA),
    path('puja/checkout/',views.CheckoutforPuja),
    path('forgot-password/',views.SendMailToPassword,name='mailpass'),
    path('changeuserpassword/<int:id>/<str:username>/',views.UserForgotPassword, name='changepass1'),
    
    #path('termsofuse/',views.Termsofuse),
    path('terms-and-condition/',views.TermsandCondition),
    path('privacy-policy/',views.PrivacyPolicy),
    path('contact-us/',views.ContactUs),
    path('shipping-policy/',views.ShippingPolicy),    
    path('refund-policy/',views.RefundPolicy),

    path('payment-status/', views.payment_return, name="payment_status"),
    path('add-to-wallet/success/', views.AddToWalletSuccessView, name="wallet_add_success"),
    path('order/success/', views.OrderSuccessView, name="order_success"),
    path('product/payment/success/', views.BuyOrderSuccessView, name="buy_now_success"),
    path('puja/payment/success/', views.PujaSuccessView, name="puja_success"),
    path('ask-astro/payment/success/', views.AskAstroSuccessView, name="askastro_success")

]