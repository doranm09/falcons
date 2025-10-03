import factory
from faker import Faker
from django.contrib.auth.models import User


fake = Faker()


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User

    # Use faker to generate realistic test data
    username = factory.Sequence(lambda n: f"user{n}")
    first_name = factory.LazyAttribute(lambda obj: fake.first_name())
    last_name = factory.LazyAttribute(lambda obj: fake.last_name())
    email = factory.LazyAttribute(lambda obj: fake.email())
    is_staff = False
    is_superuser = False

    # Password will be set to a known value for easy testing
    password = factory.PostGenerationMethodCall('set_password', 'password')
