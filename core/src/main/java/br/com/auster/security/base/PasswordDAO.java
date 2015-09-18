/*
 * Copyright (c) 2004 Auster Solutions. All Rights Reserved.
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
 * Created on 20/04/2006
 */
package br.com.auster.security.base;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Locale;
import java.util.ResourceBundle;

import org.apache.log4j.Logger;

import br.com.auster.common.util.I18n;
import br.com.auster.persistence.FetchCriteria;
import br.com.auster.persistence.jdbc.JDBCQueryHelper;
import br.com.auster.security.model.PasswordInfo;
import br.com.auster.security.model.User;

/**
 * @author framos
 * @verion $Id$
 */
public class PasswordDAO {


	protected static ResourceBundle rb;
	static {
		String pckName = PasswordInfo.class.getPackage().getName();
		rb = I18n.searchResourceBundle(pckName, "QueriesBundle", Locale.getDefault());
	}

	// attributes for the User table
	protected static final String PASSWORD_USERUID_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.userUid}", rb);
	protected static final String PASSWORD_PASSWD_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.password}", rb);
	protected static final String PASSWORD_INSERTDATE_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.insertDate}", rb);
	protected static final String PASSWORD_EXPIRDATE_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.expiredAt}", rb);
	protected static final String PASSWORD_EXPIRCOUNT_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.expirationCount}", rb);
	protected static final String PASSWORD_ERRORCOUNT_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.errorCount}", rb);
	protected static final String PASSWORD_USEDCOUNT_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.usedCount}", rb);
	protected static final String PASSWORD_LASTUSED_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.lastUsed}", rb);
	protected static final String PASSWORD_CUSTOM1_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.custom1}", rb);
	protected static final String PASSWORD_CUSTOM2_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.custom2}", rb);
	protected static final String PASSWORD_CUSTOM3_ATTR =
		JDBCQueryHelper.createSQL("${PasswordInfo.custom3}", rb);


	protected static final String SELECT_PASSWD_LIST =
		JDBCQueryHelper.createSQL(
				"select ${PasswordInfo.TABLENAME}.* from ${PasswordInfo.TABLENAME} " +
				" join ${User.TABLENAME} on ${User.uid} = ${PasswordInfo.userUid} "+
				" where ${User.login} = ? ", rb);

	protected static final String SELECT_COUNT_PASSWD =
		JDBCQueryHelper.createSQL(
				"select count(1) from ${PasswordInfo.TABLENAME} " +
				" where ${PasswordInfo.userUid} = ? ", rb);

	protected static final String UPDATE_PASSWORD_EXPIRATIONDATE =
		JDBCQueryHelper.createSQL(
				"update ${PasswordInfo.TABLENAME} set " +
				" ${PasswordInfo.expiredAt} = ? " +
				" where ${PasswordInfo.userUid} = ? and ${PasswordInfo.insertDate} = ?",
				rb);

	protected static final String DELETE_OLDEST_PASSWD =
		JDBCQueryHelper.createSQL(
				"delete from ${PasswordInfo.TABLENAME} " +
				" where ${PasswordInfo.userUid} = ? " +
				" and ${PasswordInfo.insertDate} = " +
				"  (select min(${PasswordInfo.insertDate}) from ${PasswordInfo.TABLENAME} where ${PasswordInfo.userUid} = ?) " +
				" and rownum <= 1  ",
				rb);

	protected static final String INSERT_PASSWD =
		JDBCQueryHelper.createSQL(
				"insert into ${PasswordInfo.TABLENAME} ( " +
				"${PasswordInfo.userUid}, ${PasswordInfo.password}, ${PasswordInfo.insertDate}, " +
				"${PasswordInfo.expiredAt}, ${PasswordInfo.expirationCount}, ${PasswordInfo.usedCount}, " +
				"${PasswordInfo.custom1}, ${PasswordInfo.custom2}, ${PasswordInfo.custom3} ) " +
				" values (?, ?, ?, ?, ?, ?, ?, ?, ?) ",
				rb);

	protected static final String UPDATE_PASSWORD_ERRORCOUNT_ADD =
		JDBCQueryHelper.createSQL(
				"update ${PasswordInfo.TABLENAME} set " +
				" ${PasswordInfo.errorCount} = ${PasswordInfo.errorCount} + 1 " +
				" where ${PasswordInfo.userUid} = ? and ${PasswordInfo.insertDate} = ?",
				rb);

	protected static final String UPDATE_PASSWORD_ERRORCOUNT_RESET =
		JDBCQueryHelper.createSQL(
				"update ${PasswordInfo.TABLENAME} set " +
				" ${PasswordInfo.errorCount} = 0 " +
				" where ${PasswordInfo.userUid} = ? and ${PasswordInfo.insertDate} = ?",
				rb);

	protected static final String UPDATE_PASSWORD_USERCOUNT =
		JDBCQueryHelper.createSQL(
				"update ${PasswordInfo.TABLENAME} set " +
				" ${PasswordInfo.usedCount} = ${PasswordInfo.usedCount} + 1, " +
				" ${PasswordInfo.lastUsed} = ?  where ${PasswordInfo.userUid} = ? " +
				" and ${PasswordInfo.insertDate} = ?", rb);

	private static final Logger log = Logger.getLogger(PasswordDAO.class);
	private static final I18n i18n = I18n.getInstance(DomainDAO.class);



	public PasswordInfo getCurrentPassword(Connection _conn, String _login) throws SQLException {
		FetchCriteria fetch = new FetchCriteria();
		fetch.addOrder(PASSWORD_EXPIRDATE_ATTR, false);
		fetch.setOffset(0);
		fetch.setSize(1);
		Collection passwords = this.selectPasswords(_conn, _login, fetch);
		if (passwords.size() > 0) {
			return (PasswordInfo)passwords.iterator().next();
		}
		return null;
	}

	public Collection selectPasswords(Connection _conn, String _login, FetchCriteria _fetch) throws SQLException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		Collection passwords = new LinkedList();
		try {
			String sql = JDBCQueryHelper.applyFetchParameters(_conn, SELECT_PASSWD_LIST, _fetch);
			debugSQL(sql);
			stmt = _conn.prepareStatement(sql);
			stmt.setString(1, _login);
			rset = stmt.executeQuery();
			while (rset.next()) {
				passwords.add(loadPassword(rset));
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return passwords;
	}

	public boolean updateUserPassword(Connection _conn, User _user, PasswordInfo _passwdInfo) throws SQLException {

		if (_passwdInfo.getExpirationDate() == null) {
			throw new IllegalArgumentException(i18n.getString("iae.expirationDateNotNull"));
		}
		PreparedStatement stmt = null;
		ResultSet rset = null;
		// get current password
		Timestamp now = new Timestamp(Calendar.getInstance().getTimeInMillis());
		try {
			// updating expiration date
			PasswordInfo currentPasswd = getCurrentPassword(_conn, _user.getLogin());
			if (currentPasswd != null) {
				debugSQL(UPDATE_PASSWORD_EXPIRATIONDATE);
				stmt = _conn.prepareStatement(UPDATE_PASSWORD_EXPIRATIONDATE);
				stmt.setTimestamp(1, now);
				stmt.setLong(2, _user.getUid());
				stmt.setTimestamp(3, currentPasswd.getInsertDate());
				stmt.executeUpdate();
				stmt.close();
			}
			// creating new password record
			debugSQL(INSERT_PASSWD);
			stmt = _conn.prepareStatement(INSERT_PASSWD);
			int colCount=1;
			stmt.setLong(colCount++, _user.getUid());
			stmt.setString(colCount++, _passwdInfo.getPassword());
			stmt.setTimestamp(colCount++, now);
			stmt.setTimestamp(colCount++, _passwdInfo.getExpirationDate());
			stmt.setInt(colCount++, _passwdInfo.getExpirationCount());
			stmt.setInt(colCount++, _passwdInfo.getUsedCount());
			stmt.setString(colCount++, _passwdInfo.getCustom1());
			stmt.setString(colCount++, _passwdInfo.getCustom2());
			stmt.setString(colCount++, _passwdInfo.getCustom3());
			return (stmt.executeUpdate() == 1);
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
	}

	public boolean updateUserPassword(Connection _conn, User _user, PasswordInfo _passwdInfo, int maxStoredPasswords) throws SQLException {
		if (_passwdInfo.getExpirationDate() == null) {
			throw new IllegalArgumentException(i18n.getString("iae.expirationDateNotNull"));
		}
		PreparedStatement stmt = null;
		ResultSet rset = null;
		// get current password
		Timestamp now = new Timestamp(Calendar.getInstance().getTimeInMillis());
		try {
			// checking if password already exists
			Iterator passwords = selectPasswords(_conn, _user.getLogin(), null).iterator();
			while (passwords.hasNext()){
				PasswordInfo password = (PasswordInfo) passwords.next();
				if (password.getPassword().equals(_passwdInfo.getPassword())) {
					return false;
				}
			}
			// counting
			debugSQL(SELECT_COUNT_PASSWD);
			stmt = _conn.prepareStatement(SELECT_COUNT_PASSWD);
			stmt.setLong(1, _user.getUid());
			rset = stmt.executeQuery();
			int count;
			if (rset.next()) {
				count = rset.getInt(1);
			} else {
				throw new IllegalStateException(i18n.getString("ise.selectCountEmpty"));
			}
			rset.close();
			rset = null;
			stmt.close();
			stmt = null;
			// removing old passwords
			while (count-- >= maxStoredPasswords) {
				debugSQL(DELETE_OLDEST_PASSWD);
				stmt = _conn.prepareStatement(DELETE_OLDEST_PASSWD);
				int colCount=1;
				stmt.setLong(colCount++, _user.getUid());
				stmt.setLong(colCount++, _user.getUid());
				stmt.executeUpdate();
				stmt.close();
				stmt = null;
			}

			// updating expiration date
			return updateUserPassword(_conn, _user, _passwdInfo);
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
	}

	public boolean updateErrorCount(Connection _conn, long _userId, PasswordInfo _passwdInfo, boolean _reset) throws SQLException {
		String sql = UPDATE_PASSWORD_ERRORCOUNT_ADD;
		if (_reset) {
			sql = UPDATE_PASSWORD_ERRORCOUNT_RESET;
		}
		PreparedStatement stmt = null;
		try {
			debugSQL(sql);
			stmt = _conn.prepareStatement(sql);
			stmt.setLong(1, _userId);
			stmt.setTimestamp(2, _passwdInfo.getInsertDate());
			return (stmt.executeUpdate()==1);
		} finally {
			if (stmt != null) { stmt.close(); }
		}
	}

	public boolean updateUsedCounters(Connection _conn,  long _userId, PasswordInfo _passwdInfo) throws SQLException {
		PreparedStatement stmt = null;
		try {
			debugSQL(UPDATE_PASSWORD_USERCOUNT);
			stmt = _conn.prepareStatement(UPDATE_PASSWORD_USERCOUNT);
			long timeinmilis = Calendar.getInstance().getTimeInMillis();
			stmt.setTimestamp(1, new Timestamp(timeinmilis));
			stmt.setLong(2, _userId);
			stmt.setTimestamp(3, _passwdInfo.getInsertDate());
			return (stmt.executeUpdate()==1);
		} finally {
			if (stmt != null) { stmt.close(); }
		}

	}

	protected PasswordInfo loadPassword(ResultSet _rset) throws SQLException {
		PasswordInfo passwdInfo = new PasswordInfo();
		passwdInfo.setCustom1(_rset.getString(PASSWORD_CUSTOM1_ATTR));
		passwdInfo.setCustom2(_rset.getString(PASSWORD_CUSTOM2_ATTR));
		passwdInfo.setCustom3(_rset.getString(PASSWORD_CUSTOM3_ATTR));
		passwdInfo.setExpirationCount(_rset.getInt(PASSWORD_EXPIRCOUNT_ATTR));
		passwdInfo.setUsedCount(_rset.getInt(PASSWORD_USEDCOUNT_ATTR));
		passwdInfo.setErrorCount(_rset.getInt(PASSWORD_ERRORCOUNT_ATTR));
		Timestamp temp = _rset.getTimestamp(PASSWORD_EXPIRDATE_ATTR);
		passwdInfo.setExpirationDate(_rset.getTimestamp(PASSWORD_EXPIRDATE_ATTR));
		passwdInfo.setInsertDate( _rset.getTimestamp(PASSWORD_INSERTDATE_ATTR) );
		passwdInfo.setLastUsed(_rset.getTimestamp(PASSWORD_LASTUSED_ATTR));
		passwdInfo.setPassword(_rset.getString(PASSWORD_PASSWD_ATTR));
		return passwdInfo;
	}

	private final void debugSQL(String _sql) {
		log.debug(i18n.getString("debug.sql", _sql));
	}
}
