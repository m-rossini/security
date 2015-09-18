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
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

import org.apache.log4j.Logger;

import br.com.auster.common.util.I18n;
import br.com.auster.persistence.PersistenceResourceAccessException;
import br.com.auster.persistence.jdbc.JDBCQueryHelper;
import br.com.auster.security.model.UserRoleRelation;

/**
 * @author framos
 * @verion $Id$
 */
public class UserRoleRelationDAO {



	protected static ResourceBundle rb;
	static {
		String pckName = UserRoleRelation.class.getPackage().getName();
		rb = I18n.searchResourceBundle(pckName, "QueriesBundle", Locale.getDefault());
	}

	public static final String USERROLE_TABLENAME =
		JDBCQueryHelper.createSQL("${UserRoleRelation.TABLENAME}", rb);
	public static final String USERROLE_USERUID_ATTR =
		JDBCQueryHelper.createSQL("${UserRoleRelation.userUid}", rb);
	public static final String USERROLE_ROLEUID_ATTR =
		JDBCQueryHelper.createSQL("${UserRoleRelation.roleUid}", rb);
	public static final String USERROLE_ASSIGNDATE_ATTR =
		JDBCQueryHelper.createSQL("${UserRoleRelation.assignDate}", rb);
	public static final String USERROLE_EXPIRATIONDATE_ATTR =
		JDBCQueryHelper.createSQL("${UserRoleRelation.expirationDate}", rb);


	protected static final String USERROLE_SELECT_ALL_BY_LOGIN =
		JDBCQueryHelper.createSQL("select ${UserRoleRelation.TABLENAME}.* " +
			" from ${UserRoleRelation.TABLENAME} " +
			" join ${User.TABLENAME} on ${User.TABLENAME}.${User.uid} = ${UserRoleRelation.TABLENAME}.${UserRoleRelation.userUid}" +
			" join ${Role.TABLENAME} on ${Role.TABLENAME}.${Role.uid} = ${UserRoleRelation.TABLENAME}.${UserRoleRelation.roleUid}" +
			" where LOWER(${User.TABLENAME}.${User.login}) = LOWER(?)", rb);

	protected static final String USERROLE_SELECT_ACTIVE_BY_LOGIN =
		JDBCQueryHelper.createSQL(USERROLE_SELECT_ALL_BY_LOGIN + " " +
			" and ${UserRoleRelation.TABLENAME}.${UserRoleRelation.expirationDate} is null ",
			rb);

	protected static final String USERROLE_ASSIGN =
		JDBCQueryHelper.createSQL("insert into ${UserRoleRelation.TABLENAME} ( " +
			" ${UserRoleRelation.assignDate}, ${UserRoleRelation.expirationDate}, " +
			" ${UserRoleRelation.userUid}, ${UserRoleRelation.roleUid} ) " +
			" values ( ? , null, ?, ? )", rb);

	protected static final String USERROLE_REVOKE =
		JDBCQueryHelper.createSQL("update ${UserRoleRelation.TABLENAME} set " +
			"${UserRoleRelation.expirationDate} = ? where " +
			"${UserRoleRelation.userUid} = ? and ${UserRoleRelation.roleUid} = ? and " +
			"${UserRoleRelation.expirationDate} is null", rb);

	protected static final String USERROLE_BULK_REVOKE =
		JDBCQueryHelper.createSQL("update ${UserRoleRelation.TABLENAME} set " +
			"${UserRoleRelation.expirationDate} = ? where " +
			"${UserRoleRelation.roleUid} = ? and ${UserRoleRelation.expirationDate} is null",
			rb);

	protected static final String USERROLE_BULK_ASSIGN =
		JDBCQueryHelper.createSQL("insert into ${UserRoleRelation.TABLENAME} ( " +
				" ${UserRoleRelation.assignDate}, ${UserRoleRelation.expirationDate}, " +
				" ${UserRoleRelation.userUid}, ${UserRoleRelation.roleUid} ) " +
				" ( select ?, null, ${UserRoleRelation.userUid}, ?  from " +
				"   ${UserRoleRelation.TABLENAME} where ${UserRoleRelation.roleUid} = ? )",
				rb);

	protected static final String USUARIO_ROLER =
	JDBCQueryHelper.createSQL("select distinct ${User.login} from ${User.TABLENAME}, " +
			"${Role.TABLENAME}, ${UserRoleRelation.TABLENAME} " +
			" where ${User.uid} = ${UserRoleRelation.userUid} and " +
			"       ${Role.uid} = ${UserRoleRelation.roleUid} and " +
			"       lower(${User.login} like lower(?)         and " +
			"       ${Role.name} = ?", rb);



	private static final Logger log = Logger.getLogger(UserRoleRelation.class);





	public Collection selectPermissionHistory(Connection _conn, String _name) throws SQLException, PersistenceResourceAccessException {
		return this.selectPermissionInfo(_conn, _name, UserRoleRelationDAO.USERROLE_SELECT_ALL_BY_LOGIN);
	}

	public Collection selectActivePermission(Connection _conn, String _name) throws SQLException, PersistenceResourceAccessException {
		return this.selectPermissionInfo(_conn, _name, UserRoleRelationDAO.USERROLE_SELECT_ACTIVE_BY_LOGIN);
	}

	public int assignPermission(Connection _conn, long _userId, long _roleId) throws SQLException, PersistenceResourceAccessException {
		return updatePermissionToUser(_conn, _userId, _roleId, UserRoleRelationDAO.USERROLE_ASSIGN);
	}

	public int revokePermission(Connection _conn, long _userId, long _roleId) throws SQLException, PersistenceResourceAccessException {
		return updatePermissionToUser(_conn, _userId, _roleId, UserRoleRelationDAO.USERROLE_REVOKE);
	}

	public int moveBetweenRoles(Connection _conn, long _fromRole, long _toRole) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		try {
			Timestamp now = new Timestamp(Calendar.getInstance().getTimeInMillis());
			// first, moving to new role
			debugSQL(USERROLE_BULK_ASSIGN);
			stmt = _conn.prepareStatement(USERROLE_BULK_ASSIGN);
			stmt.setTimestamp(1, now);
			stmt.setLong(2, _toRole);
			stmt.setLong(3, _fromRole);
			stmt.executeUpdate();
			stmt.close();
			// then, expiring previous one
			debugSQL(USERROLE_BULK_REVOKE);
			stmt = _conn.prepareStatement(USERROLE_BULK_REVOKE);
			stmt.setTimestamp(1, now);
			stmt.setLong(2, _fromRole);
			return stmt.executeUpdate();
		} finally {
			if (stmt != null) { stmt.close(); }
		}
	}

	public List userRole(Connection _conn, String role, String userEvent) throws SQLException{
		PreparedStatement ps = null;
		ArrayList userRoles = new ArrayList();
		ResultSet rs = null;
		try{
			debugSQL(USUARIO_ROLER);
			ps = _conn.prepareStatement(USUARIO_ROLER);
			ps.setString(1, userEvent + "%");
			ps.setString(2, role);
			rs = ps.executeQuery();
			while (rs.next()){
				userRoles.add(rs.getString(UserDAO.USER_LOGIN_ATTR));
			}
		}finally{
			if (rs != null){
				rs.close();
			}
			if (ps != null){
				ps.close();
			}
		}
		return userRoles;
	}

	private Collection selectPermissionInfo(Connection _conn, String _name, String _sql) throws SQLException, PersistenceResourceAccessException {
		Collection userRoles = new LinkedList();
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(_sql);
			stmt = _conn.prepareStatement(_sql);
			stmt.setString(1, _name);
			rset = stmt.executeQuery();
			while (rset.next()) {
				userRoles.add(loadUserPermissionFromResultset(rset));
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return userRoles;
	}

	private UserRoleRelation loadUserPermissionFromResultset(ResultSet _rset) throws SQLException {
		UserRoleRelation urole = new UserRoleRelation(_rset.getLong(USERROLE_USERUID_ATTR),
				                                      _rset.getLong(USERROLE_ROLEUID_ATTR));
		urole.setAssignDate(_rset.getTimestamp(USERROLE_ASSIGNDATE_ATTR));
		urole.setExpirationDate(_rset.getTimestamp(USERROLE_EXPIRATIONDATE_ATTR));
		return urole;
	}

	private int updatePermissionToUser(Connection _conn, long _userId, long _roleId, String _sql) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		try {
			debugSQL(_sql);
			stmt = _conn.prepareStatement(_sql);
			stmt.setTimestamp(1, new Timestamp(Calendar.getInstance().getTimeInMillis()));
			stmt.setLong(2, _userId);
			stmt.setLong(3, _roleId);
			return stmt.executeUpdate();
		} finally {
			if (stmt != null) { stmt.close(); }
		}
	}

	private final void debugSQL(String _sql) {
		log.debug("Executing sql: " + _sql);
	}
}
