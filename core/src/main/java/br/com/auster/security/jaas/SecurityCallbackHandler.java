/*
 * Copyright (c) 2004 Auster Solutions do Brasil. All Rights Reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Created on Sep 03, 2004
 */
package br.com.auster.security.jaas;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import br.com.auster.common.util.I18n;

/**
 * <p>
 * <b>Title:</b> Simple Callback Handler
 * </p>
 * <p>
 * <b>Description:</b> Implements a simple callback handler, useful when you
 * have user entered login and password before calling the login method in
 * LoginContext class. Examples are web applications. You can have the user
 * entering login and password in the application web page and after that you
 * call the login() method to validade the information, causing an inversion of
 * flow control and making easy to interact with JAAS framework.
 * </p>
 * 
 * @author Edson Tirelli
 * @version $Id$
 */
public class SecurityCallbackHandler implements CallbackHandler {

	
	
	private static final I18n i18n = I18n.getInstance(SecurityCallbackHandler.class);
	
	private String userName = null;
	private String password = null;

	
	
	public SecurityCallbackHandler() {}

	
	/**
	 * Callback method
	 * 
	 * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
	 */
	public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof TextOutputCallback) {
				// ignore it
			} else if (callbacks[i] instanceof NameCallback) {
				((NameCallback) callbacks[i]).setName(userName);
			} else if (callbacks[i] instanceof PasswordCallback) {
				((PasswordCallback) callbacks[i]).setPassword(password.toCharArray());
			} else {
				throw new UnsupportedCallbackException(callbacks[i], i18n.getString("ex.unkownCallback")); 
			}
		}
	}


	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}

	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
}
