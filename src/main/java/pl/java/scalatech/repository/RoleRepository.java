package pl.java.scalatech.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import pl.java.scalatech.entity.Role;
@Transactional
public interface RoleRepository extends JpaRepository<Role, Long>{


}
