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
import br.com.auster.security.model.Domain;

/**
 * @author framos
 * @verion $Id$
 */
public class DomainDAO {


	
	protected static ResourceBundle rb;
	static {
		String pckName = Domain.class.getPackage().getName();
		rb = I18n.searchResourceBundle(pckName, "QueriesBundle", Locale.getDefault());
	}

	// public attributes defining table name, its columns and the sequence
	//    from where UIDs will be generated
	public static final String DOMAIN_SEQUENCE  = 
		JDBCQueryHelper.createSQL("${Domain.SEQUENCE}", rb);
	public static final String DOMAIN_TABLENAME = 
		JDBCQueryHelper.createSQL("${Domain.TABLENAME}", rb);
	public static final String DOMAIN_UID_ATTR = 
		JDBCQueryHelper.createSQL("${Domain.uid}", rb);
	public static final String DOMAIN_NAME_ATTR = 
		JDBCQueryHelper.createSQL("${Domain.name}", rb);
	public static final String DOMAIN_DESCRIPTION_ATTR = 
		JDBCQueryHelper.createSQL("${Domain.description}", rb);
	public static final String DOMAIN_ACTIVE_ATTR = 
		JDBCQueryHelper.createSQL("${Domain.active}", rb);
	public static final String DOMAIN_CUSTOM1_ATTR = 
		JDBCQueryHelper.createSQL("${Domain.custom1}", rb);
	public static final String DOMAIN_CUSTOM2_ATTR = 
		JDBCQueryHelper.createSQL("${Domain.custom2}", rb);
	public static final String DOMAIN_CUSTOM3_ATTR = 
		JDBCQueryHelper.createSQL("${Domain.custom3}", rb);
	
	protected static final String DOMAIN_SELECTALL =
		JDBCQueryHelper.createSQL("select * from ${Domain.TABLENAME}", rb);
	
	protected static final String DOMAIN_COUNT =
		JDBCQueryHelper.createSQL("select count(*) from ${Domain.TABLENAME}", rb);
	
	protected static final String DOMAIN_SELECT_BY_NAME =
		JDBCQueryHelper.createSQL(DOMAIN_SELECTALL + " where ${Domain.name} = ?", rb);
	
	protected static final String DOMAIN_UPDATE_INFO =		
		JDBCQueryHelper.createSQL(
			"update ${Domain.TABLENAME} set " +
			" ${Domain.active} = ?, ${Domain.description} = ?, ${Domain.custom1} = ?, " +
			" ${Domain.custom2} = ?, ${Domain.custom3} = ? where ${Domain.name} = ?", 
			rb);
	
	protected static final String DOMAIN_INSERT_INFO =
		JDBCQueryHelper.createSQL(
			"insert into  ${Domain.TABLENAME} (" +
			" ${Domain.active}, ${Domain.description}, ${Domain.custom1}, " + 
			" ${Domain.custom2}, ${Domain.custom3}, ${Domain.name}, ${Domain.uid} ) " +
			" values ( ?, ?, ?, ?, ?, ?, '{'0'}' )", rb);
	
	protected static final String DOMAIN_REMOVE_INFO =
		JDBCQueryHelper.createSQL(
			"update ${Domain.TABLENAME} set ${Domain.active} = ? where ${Domain.name} = ?", 
			rb);
	
	private static final Logger log = Logger.getLogger(DomainDAO.class);
	private static final I18n i18n = I18n.getInstance(DomainDAO.class);	
	
	
	
	
	public Domain selectSingleDomainByName(Connection conn, String _name) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(DOMAIN_SELECT_BY_NAME);
			stmt = conn.prepareStatement(DOMAIN_SELECT_BY_NAME);
			stmt.setString(1, _name);
			rset = stmt.executeQuery();
			if (rset.next()) {
				return loadDomainFromResultset(rset);
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return null;
	}

	public Collection selectAllDomains(Connection conn, FetchCriteria _fetch) throws SQLException, PersistenceResourceAccessException {
		return doSelect(conn, _fetch, DOMAIN_SELECTALL);
	}	
	
	public int countDomains(Connection conn) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(DOMAIN_COUNT);
			stmt = conn.prepareStatement(DOMAIN_COUNT);
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
	
	public int updateSingleDomain(Connection conn, Domain _domain) throws SQLException, PersistenceResourceAccessException {
		if (executeSingleUpdate(conn, DOMAIN_UPDATE_INFO, _domain) != 1) {
			throw new SQLException(i18n.getString("dao.updateError"));
		}
		return 1;
	}

	public long insertDomain(Connection conn, Domain _domain) throws SQLException, PersistenceResourceAccessException {
		long uid = JDBCSequenceHelper.nextValue(conn, DOMAIN_SEQUENCE);
		_domain.setUid(uid);
		String sql = MessageFormat.format(DOMAIN_INSERT_INFO, new Object[] { String.valueOf(uid) } );
		if (executeSingleUpdate(conn, sql, _domain) != 1) {
			throw new SQLException(i18n.getString("dao.notInserted"));
		}
		return uid;
	}	

	public int deactivateDomain(Connection _conn, Domain _domain) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		try {
			debugSQL(DOMAIN_REMOVE_INFO);
			stmt = _conn.prepareStatement(DOMAIN_REMOVE_INFO);
			int colIdx = 1;
			stmt.setString(colIdx++, decodeActiveFlag(_domain.isActive()));
			stmt.setString(colIdx++, _domain.getDomainName());	
			return stmt.executeUpdate();
		} finally {
			if (stmt != null) { stmt.close(); }
		}
	}	
	
	private int executeSingleUpdate(Connection _conn, String _sql, Domain _domain) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(_sql);
			stmt = _conn.prepareStatement(_sql);
			int colIdx = 1;
			stmt.setString(colIdx++, decodeActiveFlag(_domain.isActive()));
			stmt.setString(colIdx++, _domain.getDescription());
			stmt.setString(colIdx++, _domain.getCustom1());
			stmt.setString(colIdx++, _domain.getCustom2());
			stmt.setString(colIdx++, _domain.getCustom3());
			stmt.setString(colIdx++, _domain.getDomainName());	
			return stmt.executeUpdate();
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
	}
	
	private final String decodeActiveFlag(boolean _active) {
		return (_active ? "D" : "A");
	}
	
	private final boolean encodeActiveFlag(String _active) {
		return ((_active != null) &&  "A".equals(_active));
	}
		
	private Domain loadDomainFromResultset(ResultSet _rset) throws SQLException {
		Domain domain = new Domain(_rset.getString(DOMAIN_NAME_ATTR));
		// setting BaseUser attributes
		domain.setDescription(_rset.getString(DOMAIN_DESCRIPTION_ATTR));
		domain.setActive(encodeActiveFlag(_rset.getString(DOMAIN_ACTIVE_ATTR)));
		// setting CustomizableEntity attributes
		domain.setUid(_rset.getLong(DOMAIN_UID_ATTR));
		domain.setCustom1(_rset.getString(DOMAIN_CUSTOM1_ATTR));
		domain.setCustom2(_rset.getString(DOMAIN_CUSTOM2_ATTR));
		domain.setCustom3(_rset.getString(DOMAIN_CUSTOM3_ATTR));
		return domain;
	}
	
	private Collection doSelect(Connection conn, FetchCriteria _fetch, String _sql) throws SQLException, PersistenceResourceAccessException {
		Collection selectedDomains = new LinkedList();
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			String sql = JDBCQueryHelper.applyFetchParameters(conn, _sql, _fetch);
			debugSQL(sql);
			stmt = conn.prepareStatement(sql);
			rset = stmt.executeQuery();
			while (rset.next()) {
				selectedDomains.add(loadDomainFromResultset(rset));
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return selectedDomains;
	}

	private final void debugSQL(String _sql) {
		log.debug(i18n.getString("debug.sql", _sql));
	}	
}
