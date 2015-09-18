/*
 * Copyright (c) 2004-2006 Auster Solutions. All Rights Reserved.
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
 * Created on 23/09/2006
 */
package br.com.auster.security.model;

import java.io.Serializable;
import java.sql.Date;
import java.sql.Timestamp;
import java.util.Calendar;

import br.com.auster.common.util.I18n;
import br.com.auster.om.reference.CustomizableEntity;

/**
 * This class represents each time a user's password was updated.
 * <p>
 * Each occurrence identifies a single password, the range of time it was valid,
 * 	how many times the user used the system while using this password and when
 * 	was the last date/time he did it.
 * <p>
 * Also, instances of this class hold information about the expiration of the password.
 *   There are two ways a password is expired : a pre-defined date or a pre-defined number
 *   of times he/she used this password.
 * <p>
 * By default, the {@link #expirationCount} attribute is assigned with {@value #DISABLED_EXPIRATION_COUTING}
 *   constant, which indicates that this password will not expire due to the number of times
 *   the user logged in. The {@link #expiredAt} attribute is also defaulted, to 30 days counting
 *   from the current date.
 * <p>
 * Any other logic related to expiring passwords must be dealt outside this library.
 * <p>
 * Passwords have only two states: active or expired. To identify a user that was blocked
 * 	due to a excessive number of tries or a timeout in inactivity, for example, checkout the
 * 	{@link User#status} attribute.
 * <p>
 *
 * @author framos
 * @version $Id$
 */
public class PasswordInfo extends CustomizableEntity implements Serializable {


	private static final I18n i18n = I18n.getInstance(PasswordInfo.class);

	public static final int DISABLED_EXPIRATION_COUTING = -1;

	protected String password;
	protected Timestamp insertDate;
	protected Timestamp expiredAt;
	protected int expirationCount;
	protected int usedCount;
	protected int errorCount;
	protected Timestamp lastUsed;
	protected transient boolean inWarnRange;


	public PasswordInfo() {
		super();
		this.onCreate();
	}

	public PasswordInfo(long _uid) {
		super(_uid);
		this.onCreate();
	}


	public String getPassword() {
		return this.password;
	}
	public void setPassword(String _password) {
		this.password = _password;
	}

	public Timestamp getInsertDate() {
		return this.insertDate;
	}
	public void setInsertDate(Timestamp _date) {
		if (_date == null) {
			throw new IllegalArgumentException(i18n.getString("iae.insertDateNotNull"));
		}
		this.insertDate = _date;
	}

	public Timestamp getExpirationDate() {
		return this.expiredAt;
	}
	public void setExpirationDate(Timestamp _date) {
		if (_date == null) {
			throw new IllegalArgumentException(i18n.getString("iae.expirationDateNotNull"));
		}
		this.expiredAt = _date;
	}

	public int getExpirationCount() {
		return this.expirationCount;
	}
	public void setExpirationCount(int _count) {
		this.expirationCount = _count;
	}

	public int getUsedCount() {
		return this.usedCount;
	}
	public void setUsedCount(int _count) {
		this.usedCount = _count;
	}

	public Timestamp getLastUsed() {
		return this.lastUsed;
	}
	public void setLastUsed(Timestamp _date) {
		this.lastUsed = _date;
	}

	public int getErrorCount() {
		return this.errorCount;
	}
	public void setErrorCount(int _count) {
		this.errorCount = _count;
	}

	public boolean isInWarningRange() {
		return this.inWarnRange;
	}

	public void setInWarningRange(boolean _inWarnRange) {
		this.inWarnRange = _inWarnRange;
	}


	protected void onCreate() {
		this.expirationCount = DISABLED_EXPIRATION_COUTING;
		Calendar c = Calendar.getInstance();
		c.add(Calendar.DATE, 30);
		this.expiredAt = new Timestamp(c.getTimeInMillis());
	}
}
