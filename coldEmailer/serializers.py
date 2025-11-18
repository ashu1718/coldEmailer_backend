from django.contrib.auth import get_user_model
from rest_framework import serializers 

User= get_user_model()

class SignUpSerializer(serializers.ModelSerializer):
    password= serializers.CharField(write_only= True, min_length=8)

    class Meta:
        model= User
        fields=["id", "email", "password", "first_name","last_name"]

    def create(self, validated_data):
        user= User(
            username= validated_data["email"],
            email= validated_data["email"],
            first_name= validated_data.get("first_name",""),
            last_name= validated_data.get("last_name",""),
        )

        user.set_password(validated_data["password"])
        user.save()
        return user