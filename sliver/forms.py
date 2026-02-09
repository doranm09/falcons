from django import forms

from .models import Teamserver


class TeamserverForm(forms.ModelForm):
    class Meta:
        model = Teamserver
        fields = [
            "name",
            "host",
            "port",
            "ca_cert",
            "certificate",
            "private_key",
        ]
        widgets = {
            "ca_cert": forms.Textarea(attrs={"rows": 3}),
            "certificate": forms.Textarea(attrs={"rows": 3}),
            "private_key": forms.Textarea(attrs={"rows": 3}),
        }

    def clean(self):
        cleaned = super().clean()
        certificate = cleaned.get("certificate")
        private_key = cleaned.get("private_key")

        if bool(certificate) ^ bool(private_key):
            raise forms.ValidationError("Certificate and private key must be provided together.")

        return cleaned

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            classes = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{classes} form-control".strip()
