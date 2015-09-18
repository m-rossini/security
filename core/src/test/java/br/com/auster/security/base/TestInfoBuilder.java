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
 * Created on 28/09/2006
 */
package br.com.auster.security.base;

import java.sql.Connection;
import java.sql.Date;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Calendar;

import br.com.auster.security.model.Domain;
import br.com.auster.security.model.PasswordInfo;
import br.com.auster.security.model.Role;
import br.com.auster.security.model.User;

/**
 * @author framos
 * @version $Id$
 */
public final class TestInfoBuilder {


	static public User getUser1() {
		User user = new User();
		user.setLocked(false);
		user.setFirstName("MyName");
		user.setLastName("Surname");
		user.setEmail("test@auster.com.br");
		user.setLogin("test@auster.com.br");
		return user;
	}

	static public User getUser2() {
		User user = new User();
		user.setLocked(false);
		user.setFirstName("MyName 2");
		user.setLastName("Surname 2");
		user.setEmail("test2@auster.com.br");
		user.setLogin("test2@auster.com.br");
		return user;
	}

	static public User getUser3() {
		User user = new User();
		user.setLocked(false);
		user.setLastName("Surname 3");
		user.setEmail("test3@auster.com.br");
		user.setLogin("test3@auster.com.br");
		return user;
	}

	static public PasswordInfo getPassword() {
		PasswordInfo password = new PasswordInfo();
		password.setPassword("mypass");
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MONTH, 3);
		password.setExpirationDate(new Timestamp(c.getTimeInMillis()));
		return password;
	}

	static public Role getAdminRole() {
		Role role = new Role("admin");
		role.setDescription("Grupo de administradores");
		return role;
	}

	static public Role getGuestRole() {
		Role role = new Role("guest");
		role.setDescription("Usuários convidados");
		return role;
	}

	static public Role getAnalystRole() {
		Role role = new Role("analyst");
		role.setDescription("Grupo de analistas");
		return role;
	}

	static public Domain getRequestMgmtDomain() {
		Domain d = new Domain("REQMGMT");
		d.setDescription("Can run on-demand requests");
		return d;
	}

	static public Domain getUserMgmtDomain() {
		Domain d = new Domain("USERMGMT");
		d.setDescription("Can update/create users and groups");
		return d;
	}

	static public Domain getRequestViewDomain() {
		Domain d = new Domain("REQVIEW");
		d.setDescription("Can view request results");
		return d;
	}

	static public Domain getReportViewDomain() {
		Domain d = new Domain("DYNREPORT");
		d.setDescription("Can run/view dynamic reports");
		return d;
	}



	// setup time methods

	public static void clearDatabase(Connection c) throws SQLException {
		Statement s = null;
		try {
			s = c.createStatement();
			s.executeUpdate("delete from auth_user_roles");
			s.executeUpdate("delete from auth_domain_roles");
			s.executeUpdate("delete from auth_passwd_history");
			s.executeUpdate("delete from auth_role");
			s.executeUpdate("delete from auth_domain");
			s.executeUpdate("delete from auth_user");
			c.commit();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (s != null) { s.close(); }
		}

	}
}
