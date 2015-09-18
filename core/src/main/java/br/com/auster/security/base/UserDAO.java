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
import java.text.MessageFormat;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Locale;
import java.util.ResourceBundle;

import org.apache.log4j.Logger;

import br.com.auster.common.util.I18n;
import br.com.auster.persistence.FetchCriteria;
import br.com.auster.persistence.PersistenceResourceAccessException;
import br.com.auster.persistence.jdbc.JDBCQueryHelper;
import br.com.auster.persistence.jdbc.JDBCSequenceHelper;
import br.com.auster.security.model.User;

/**
 * @author framos
 * @verion $Id$
 */
public class UserDAO {


	protected static ResourceBundle rb;
	static {
		String pckName = User.class.getPackage().getName();
		rb = I18n.searchResourceBundle(pckName, "QueriesBundle", Locale.getDefault());
	}
	
	// public attributes defining table name, its columns and the sequence
	//    from where UIDs will be generated
	public static final String USER_SEQUENCE = 
		JDBCQueryHelper.createSQL("${User.SEQUENCE}", rb);
	public static final String USER_TABLENAME = 
		JDBCQueryHelper.createSQL("${User.TABLENAME}", rb);
	public static final String USER_UID_ATTR = 
		JDBCQueryHelper.createSQL("${User.uid}", rb);
	public static final String USER_LOGIN_ATTR = 
		JDBCQueryHelper.createSQL("${User.login}", rb);
	public static final String USER_EMAIL_ATTR = 
		JDBCQueryHelper.createSQL("${User.email}", rb);
	public static final String USER_LASTNAME_ATTR = 
		JDBCQueryHelper.createSQL("${User.lastName}", rb);
	public static final String USER_FIRSTNAME_ATTR = 
		JDBCQueryHelper.createSQL("${User.firstName}", rb);
	public static final String USER_STATUS_ATTR = 
		JDBCQueryHelper.createSQL("${User.status}", rb);
	public static final String USER_CUSTOM1_ATTR = 
		JDBCQueryHelper.createSQL("${User.custom1}", rb);
	public static final String USER_CUSTOM2_ATTR = 
		JDBCQueryHelper.createSQL("${User.custom2}", rb);
	public static final String USER_CUSTOM3_ATTR =  
		JDBCQueryHelper.createSQL("${User.custom3}", rb);
		
	protected static final String USER_SELECTALL = 
		JDBCQueryHelper.createSQL("select * from ${User.TABLENAME}", rb);
	
	protected static final String USER_SELECT_BY_LOGIN =
		JDBCQueryHelper.createSQL(USER_SELECTALL + " where LOWER(${User.login}) = LOWER(?)", rb);

	protected static final String USER_SELECT_BY_UID =
		JDBCQueryHelper.createSQL(USER_SELECTALL + " where ${User.uid} = ?", rb);

	protected static final String  USER_COUNT =
		JDBCQueryHelper.createSQL("select count(*) from ${User.TABLENAME}", rb);
	
	protected static final String USER_UPDATE_INFO_AND_STATUS =
		JDBCQueryHelper.createSQL(
			"update ${User.TABLENAME} set ${User.firstName} = ?, ${User.lastName} = ?, "+
			"${User.email} = ?, ${User.status} = ?, ${User.custom1} = ?, " +
			"${User.custom2} = ?, ${User.custom3} = ? where " +
			"${User.login} = ? ", rb);

	protected static final String USER_UPDATE_INFO =
		JDBCQueryHelper.createSQL(
			"update ${User.TABLENAME} set ${User.firstName} = ?, ${User.lastName} = ?, "+
			"${User.email} = ?, ${User.custom1} = ?, ${User.custom2} = ?, " +
			"${User.custom3} = ? where ${User.login} = ? ", rb);

	protected static final String USER_INSERT_INFO = 
		JDBCQueryHelper.createSQL(
			"insert into ${User.TABLENAME} ( ${User.firstName}, ${User.lastName}, ${User.email}, " +
			" ${User.status}, ${User.custom1} , ${User.custom2}, ${User.custom3}, " + 
			" ${User.login}, ${User.uid} ) " +
			" values ( ?, ?, ?, ?, ?, ?, ?, ?, '{'0'}' )", rb);
	

	private static final Logger log = Logger.getLogger(UserDAO.class);
	private static final I18n i18n = I18n.getInstance(UserDAO.class);
	
	
	
	public User selectSingleUserByLogin(Connection conn, String _login) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(UserDAO.USER_SELECT_BY_LOGIN);
			stmt = conn.prepareStatement(USER_SELECT_BY_LOGIN);
			stmt.setString(1, _login);
			rset = stmt.executeQuery();
			if (rset.next()) {
				return loadUserFromResultset(rset);
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return null;
	}

	public User selectSingleUser(Connection conn, long _uid) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(UserDAO.USER_SELECT_BY_UID);
			stmt = conn.prepareStatement(USER_SELECT_BY_UID);
			stmt.setLong(1, _uid);
			rset = stmt.executeQuery();
			if (rset.next()) {
				return loadUserFromResultset(rset);
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return null;
	}
	
	public Collection selectAllUsers(Connection conn, FetchCriteria _fetch) throws SQLException, PersistenceResourceAccessException {
		Collection selectedUsers = new LinkedList();
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			String sql = JDBCQueryHelper.applyFetchParameters(conn, UserDAO.USER_SELECTALL, _fetch);
			debugSQL(sql);
			stmt = conn.prepareStatement(sql);
			rset = stmt.executeQuery();
			while (rset.next()) {
				selectedUsers.add(loadUserFromResultset(rset));
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return selectedUsers;
	}	
	
	public int countUsers(Connection conn) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(USER_COUNT);
			stmt = conn.prepareStatement(USER_COUNT);
			rset = stmt.executeQuery();
			if (rset.next()) {
				return rset.getInt(1);
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return 0;
	}
	
	public int updateUserStatus(Connection conn, User _user) throws SQLException, PersistenceResourceAccessException {
		if (executeSingleUpdate(conn, USER_UPDATE_INFO_AND_STATUS, _user, false) != 1) {
			throw new SQLException(i18n.getString("dao.updateError"));
		}
		return 1;
	}
	
	public int updateSingleUser(Connection conn, User _user) throws SQLException, PersistenceResourceAccessException {
		if (executeSingleUpdate(conn, USER_UPDATE_INFO, _user, true) != 1) {
			throw new SQLException(i18n.getString("dao.updateError"));
		}
		return 1;
	}

	public long insertUser(Connection conn, User _user) throws SQLException, PersistenceResourceAccessException {
		long uid = JDBCSequenceHelper.nextValue(conn, USER_SEQUENCE);
		_user.setUid(uid);
		String sql = MessageFormat.format(USER_INSERT_INFO, new Object[] { String.valueOf(uid) } );
		if (executeSingleUpdate(conn, sql, _user, false) != 1) {
			throw new SQLException(i18n.getString("dao.notInserted"));
		}
		return uid;
	}	
	
	private int executeSingleUpdate(Connection _conn, String _sql, User _user, boolean _skipStatus) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(_sql);
			stmt = _conn.prepareStatement(_sql);
			int colIdx = 1;
			stmt.setString(colIdx++, _user.getFirstName());
			stmt.setString(colIdx++, _user.getLastName());
			stmt.setString(colIdx++, _user.getEmail());		
			if (!_skipStatus) {
				stmt.setString(colIdx++, decodeLockFlag(_user.isLocked()));
			}
			stmt.setString(colIdx++, _user.getCustom1());
			stmt.setString(colIdx++, _user.getCustom2());
			stmt.setString(colIdx++, _user.getCustom3());
			stmt.setString(colIdx++, _user.getLogin());		
			return stmt.executeUpdate();
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
	}
	
	private User loadUserFromResultset(ResultSet _rset) throws SQLException {
		User user = new User();
		// setting BaseUser attributes
		user.setUid(_rset.getLong(USER_UID_ATTR));
		user.setEmail(_rset.getString(USER_EMAIL_ATTR));
		user.setLogin(_rset.getString(USER_LOGIN_ATTR));
		user.setFirstName(_rset.getString(USER_FIRSTNAME_ATTR));
		user.setLastName(_rset.getString(USER_LASTNAME_ATTR));
		user.setLocked(encodeLockFlag(_rset.getString(USER_STATUS_ATTR)));
		// setting CustomizableEntity attributes
		user.setCustom1(_rset.getString(USER_CUSTOM1_ATTR));
		user.setCustom2(_rset.getString(USER_CUSTOM2_ATTR));
		user.setCustom3(_rset.getString(USER_CUSTOM3_ATTR));
		return user;
	}
	
	private final String decodeLockFlag(boolean _locked) {
		return (_locked ? "L" : "A");
	}
	
	private final boolean encodeLockFlag(String _locked) {
		return ((_locked != null) &&  "L".equals(_locked));
	}

	private final void debugSQL(String _sql) {
		log.debug(i18n.getString("debug.sql", _sql));
	}
}
