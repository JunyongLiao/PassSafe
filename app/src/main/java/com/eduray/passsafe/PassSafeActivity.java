package com.eduray.passsafe;

import android.app.LoaderManager.LoaderCallbacks;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Loader;
import android.database.Cursor;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioButton;

/**
 * The password generate screen .
 */
public class PassSafeActivity extends AppCompatActivity implements LoaderCallbacks<Cursor> {
    // UI references.
    private EditText mBaseView;
    private EditText mApplicationView;

    private RadioButton passwordTypeHex;
    private RadioButton passwordTypeNumber;
    private RadioButton passwordTypeLetter;
    private RadioButton passwordTypeMix;

    private EditText mPasswordLengthView;
    private EditText mPasswordView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pass_safe);
        // Set up the login form.
        mBaseView = (AutoCompleteTextView) findViewById(R.id.base);

        mApplicationView = (EditText) findViewById(R.id.application);
        mPasswordLengthView = (EditText) findViewById(R.id.passwordLength);

        passwordTypeHex = (RadioButton)findViewById(R.id.pass_type_hex);
        passwordTypeNumber = (RadioButton)findViewById(R.id.pass_type_number);
        passwordTypeLetter = (RadioButton)findViewById(R.id.pass_type_letter);
        passwordTypeMix = (RadioButton)findViewById(R.id.pass_type_mix);

        mPasswordView = (EditText) findViewById(R.id.safePassword);

        Button mPasswordGenerateButton = (Button) findViewById(R.id.pass_generate_button);
        mPasswordGenerateButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                generatePassword();
            }
        });
    }

    /**
     * Attempts to sign in or register the account specified by the login form.
     * If there are form errors (invalid email, missing fields, etc.), the
     * errors are presented and no actual login attempt is made.
     */
    private void generatePassword() {
        // Reset errors.
        mBaseView.setError(null);
        mApplicationView.setError(null);
        mPasswordLengthView.setError(null);

        // Store values at the time of the login attempt.
        String base = mBaseView.getText().toString();
        String application = mApplicationView.getText().toString();

        String passwordType = null;
        if(passwordTypeHex.isChecked()){
            passwordType = "hex";
        }else if(passwordTypeNumber.isChecked()){
            passwordType = "number";
        }else if(passwordTypeLetter.isChecked()){
            passwordType = "letter";
        }else if(passwordTypeMix.isChecked()){
            passwordType = "mix";
        }

        int passwordLength = Integer.parseInt(mPasswordLengthView.getText().toString());

        // Check for a valid password, if the user entered one.
        if (TextUtils.isEmpty(base)) {
            mApplicationView.setError(getString(R.string.error_invalid_base));
            return;
        }
        if (TextUtils.isEmpty(application)) {
            mApplicationView.setError(getString(R.string.error_invalid_application));
            return;
        }
        if (passwordLength <= 0 || passwordLength > 64) {
            mApplicationView.setError(getString(R.string.error_invalid_length));
            return;
        }

        PasswordGenerator passwordGenerator = new PasswordGenerator(passwordType);
        String passwordKey = base + ":" + application;
        String password = passwordGenerator.hex_md5(passwordKey);
        if(passwordLength < password.length()) {
            password = password.substring(0, passwordLength);
        }

        mPasswordView.setText(password);

        ClipData clip = ClipData.newPlainText("password", password);
        ClipboardManager cmb = (ClipboardManager) this.getBaseContext().getSystemService(Context.CLIPBOARD_SERVICE);
        cmb.setPrimaryClip(clip);
    }

    @Override
    public void onLoadFinished(Loader<Cursor> cursorLoader, Cursor cursor) {
        cursor.moveToFirst();
    }

    @Override
    public void onLoaderReset(Loader<Cursor> cursorLoader) {
    }

    @Override
    public void onStart() {
        super.onStart();
    }

    @Override
    public void onStop() {
        super.onStop();
    }

    @Override
    public Loader<Cursor> onCreateLoader(int id, Bundle args) {
        return null;
    }
}

